using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Lakerfield.Acme;

public sealed class AcmeDnsHostedService : BackgroundService
{
  private const ushort ClassIn = 1;
  private const ushort TypeTxt = 16;

  private const byte RCodeNoError = 0;
  private const byte RCodeFormErr = 1;
  private const byte RCodeNxDomain = 3;
  private const byte RCodeRefused = 5;

  private readonly AcmeDnsServerOptions _options;
  private readonly IAcmeDnsChallengeStore _store;
  private readonly ILogger<AcmeDnsHostedService> _logger;

  private UdpClient? _udp;

  public AcmeDnsHostedService(
      IOptions<AcmeDnsServerOptions> options,
      IAcmeDnsChallengeStore store,
      ILogger<AcmeDnsHostedService> logger)
  {
    _options = options.Value;
    _store = store;
    _logger = logger;

    if (string.IsNullOrWhiteSpace(_options.ZoneName))
      throw new InvalidOperationException("AcmeDnsServerOptions.ZoneName is required.");

    if (_options.Port is < 1 or > 65535)
      throw new InvalidOperationException("AcmeDnsServerOptions.Port must be between 1 and 65535.");
  }

  protected override async Task ExecuteAsync(CancellationToken stoppingToken)
  {
    var bindEndPoint = new IPEndPoint(_options.BindAddress, _options.Port);

    _udp = new UdpClient(bindEndPoint.AddressFamily);
    _udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
    _udp.Client.Bind(bindEndPoint);

    _logger.LogInformation(
        "ACME DNS server started on {BindAddress}:{Port} for zone {ZoneName}",
        _options.BindAddress,
        _options.Port,
        _options.ZoneName);

    while (!stoppingToken.IsCancellationRequested)
    {
      UdpReceiveResult received;

      try
      {
        received = await _udp.ReceiveAsync(stoppingToken);
      }
      catch (OperationCanceledException)
      {
        break;
      }
      catch (ObjectDisposedException)
      {
        break;
      }
      catch (Exception ex)
      {
        _logger.LogError(ex, "Failure while receiving DNS query.");
        continue;
      }

      byte[] response;

      try
      {
        response = CreateResponse(received.Buffer);
      }
      catch (Exception ex)
      {
        _logger.LogDebug(ex, "Invalid DNS query received from {RemoteEndPoint}", received.RemoteEndPoint);
        continue;
      }

      if (response.Length == 0)
        continue;

      try
      {
        await _udp.SendAsync(response, response.Length, received.RemoteEndPoint);
      }
      catch (Exception ex)
      {
        _logger.LogDebug(ex, "Error while sending DNS response to {RemoteEndPoint}", received.RemoteEndPoint);
      }
    }

    _logger.LogInformation("ACME DNS server stopped.");
  }

  public override void Dispose()
  {
    _udp?.Dispose();
    base.Dispose();
  }

  private byte[] CreateResponse(byte[] queryBytes)
  {
    var query = queryBytes.AsSpan();

    if (query.Length < 12)
      return Array.Empty<byte>();

    ushort id = ReadUInt16(query, 0);
    ushort requestFlags = ReadUInt16(query, 2);
    ushort qdCount = ReadUInt16(query, 4);

    if (qdCount != 1)
      return CreateSimpleErrorResponse(id, requestFlags, RCodeFormErr);

    int offset = 12;
    string qname;

    try
    {
      qname = NormalizeName(ReadName(query, ref offset));
    }
    catch
    {
      return CreateSimpleErrorResponse(id, requestFlags, RCodeFormErr);
    }

    if (offset + 4 > query.Length)
      return CreateSimpleErrorResponse(id, requestFlags, RCodeFormErr);

    ushort qtype = ReadUInt16(query, offset);
    ushort qclass = ReadUInt16(query, offset + 2);
    offset += 4;

    int questionEnd = offset;

    if (qclass != ClassIn)
      return CreateSimpleErrorResponse(id, requestFlags, RCodeRefused);

    byte rcode;
    int ttl = _options.DefaultTtl;
    List<byte[]> answerRdatas = new();

    if (!IsInZone(qname, _options.ZoneName))
    {
      rcode = RCodeRefused;
    }
    else if (_store.TryGetLiveTxtRecord(qname, out var record))
    {
      ttl = record.Ttl;

      if (qtype == TypeTxt)
      {
        foreach (var value in record.Values)
        {
          answerRdatas.Add(BuildTxtRData(value));
        }
      }

      // Bestaat wel, maar ander type: NOERROR met lege answer
      rcode = RCodeNoError;
    }
    else
    {
      rcode = RCodeNxDomain;
    }

    var response = new List<byte>(Math.Max(512, query.Length + 128));

    // Header
    WriteUInt16(response, id);
    WriteUInt16(response, BuildResponseFlags(requestFlags, rcode));
    WriteUInt16(response, 1); // QDCOUNT
    WriteUInt16(response, (ushort)answerRdatas.Count); // ANCOUNT
    WriteUInt16(response, 0); // NSCOUNT
    WriteUInt16(response, 0); // ARCOUNT

    // Question echo
    response.AddRange(query.Slice(12, questionEnd - 12).ToArray());

    foreach (var rdata in answerRdatas)
    {
      // Pointer naar originele qname op offset 12
      WriteUInt16(response, 0xC00C);
      WriteUInt16(response, TypeTxt);
      WriteUInt16(response, ClassIn);
      WriteUInt32(response, (uint)ttl);
      WriteUInt16(response, (ushort)rdata.Length);
      response.AddRange(rdata);
    }

    return response.ToArray();
  }

  private static byte[] BuildTxtRData(string value)
  {
    var payload = Encoding.UTF8.GetBytes(value);

    if (payload.Length > 255)
      throw new InvalidOperationException("TXT value >255 bytes is in this minimal implementation not split.");

    var result = new byte[payload.Length + 1];
    result[0] = (byte)payload.Length;
    Buffer.BlockCopy(payload, 0, result, 1, payload.Length);
    return result;
  }

  private static ushort BuildResponseFlags(ushort requestFlags, byte rcode)
  {
    ushort flags = 0;

    flags |= 0x8000; // QR
    flags |= 0x0400; // AA
    flags |= (ushort)(requestFlags & 0x7800); // OPCODE
    flags |= (ushort)(requestFlags & 0x0100); // RD
    flags |= rcode;

    return flags;
  }

  private static byte[] CreateSimpleErrorResponse(ushort id, ushort requestFlags, byte rcode)
  {
    var response = new List<byte>(12);
    WriteUInt16(response, id);
    WriteUInt16(response, BuildResponseFlags(requestFlags, rcode));
    WriteUInt16(response, 0);
    WriteUInt16(response, 0);
    WriteUInt16(response, 0);
    WriteUInt16(response, 0);
    return response.ToArray();
  }

  private static ushort ReadUInt16(ReadOnlySpan<byte> buffer, int offset)
      => BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(offset, 2));

  private static void WriteUInt16(List<byte> buffer, ushort value)
  {
    Span<byte> tmp = stackalloc byte[2];
    BinaryPrimitives.WriteUInt16BigEndian(tmp, value);
    buffer.AddRange(tmp.ToArray());
  }

  private static void WriteUInt32(List<byte> buffer, uint value)
  {
    Span<byte> tmp = stackalloc byte[4];
    BinaryPrimitives.WriteUInt32BigEndian(tmp, value);
    buffer.AddRange(tmp.ToArray());
  }

  private static string ReadName(ReadOnlySpan<byte> message, ref int offset)
  {
    var labels = new List<string>();
    int current = offset;
    bool jumped = false;
    int jumps = 0;

    while (true)
    {
      if (current >= message.Length)
        throw new FormatException("Name exceeds message length.");

      byte len = message[current];

      if (len == 0)
      {
        current++;

        if (!jumped)
          offset = current;

        break;
      }

      if ((len & 0xC0) == 0xC0)
      {
        if (current + 1 >= message.Length)
          throw new FormatException("Incomplete compression pointer.");

        ushort pointer = (ushort)(((len & 0x3F) << 8) | message[current + 1]);

        if (++jumps > 16)
          throw new FormatException("Too many compression jumps.");

        if (!jumped)
        {
          offset = current + 2;
          jumped = true;
        }

        current = pointer;
        continue;
      }

      if ((len & 0xC0) != 0)
        throw new FormatException("Invalid label.");

      current++;

      if (current + len > message.Length)
        throw new FormatException("Label exceeds message length.");

      labels.Add(Encoding.ASCII.GetString(message.Slice(current, len)));
      current += len;
    }

    return labels.Count == 0 ? "." : string.Join('.', labels);
  }

  private static string NormalizeName(string name)
      => name.Trim().TrimEnd('.');

  private static bool IsInZone(string fqdn, string zoneName)
  {
    zoneName = NormalizeName(zoneName);

    return fqdn.Equals(zoneName, StringComparison.OrdinalIgnoreCase)
        || fqdn.EndsWith("." + zoneName, StringComparison.OrdinalIgnoreCase);
  }
}
