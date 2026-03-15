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
}
