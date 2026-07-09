using System;
using System.Collections.Generic;
using System.Text;

namespace Lakerfield.Acme;

public static class WellKnownServers
{
  /// <summary>
  /// Let's Encrypt ACME production server
  /// </summary>
  public static Uri LetsEncrypt { get; } = new Uri("https://acme-v02.api.letsencrypt.org/directory");

  /// <summary>
  /// Let's Encrypt staging server
  /// </summary>
  public static Uri LetsEncryptStaging { get; } = new Uri("https://acme-staging-v02.api.letsencrypt.org/directory");

  /// <summary>
  /// ZeroSSL production server
  /// </summary>
  public static Uri ZeroSsl { get; } = new Uri("https://acme.zerossl.com/v2/DV90");

}
