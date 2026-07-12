using System;
using System.Net;

namespace Lakerfield.Acme;

public sealed class AcmeDnsServerOptions
{
  public IPAddress BindAddress { get; set; } = IPAddress.Any;

  public int Port { get; set; } = 53;

  /// <summary>
  /// Authoritative zone
  /// </summary>
  public string ZoneName { get; set; } = "";

  public int DefaultTtl { get; set; } = 30;

  /// <summary>
  /// Optional callback invoked for every TXT query inside the zone:
  /// (qname, remote endpoint, record found).
  /// </summary>
  public Action<string, IPEndPoint, bool>? OnTxtQuery { get; set; }
}
