using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Lakerfield.Acme.Models;

/// <summary>
/// ACME Certificate Bundle conform RFC 8555 §7.5
/// Contains private key and certificate chain
/// </summary>
public class CertificateBundle
{
  /// <summary>
  /// Private key in PEM format
  /// </summary>
  public string PrivateKey { get; set; } = default!;

  /// <summary>
  /// Leaf certificate (PEM format)
  /// </summary>
  [JsonPropertyName("certificate")]
  public string Certificate { get; set; } = default!;

  /// <summary>
  /// Intermediate certificate(s) in PEM format, if provided
  /// </summary>
  public string? IntermediateCertificate { get; set; }

  /// <summary>
  /// Full chain (leaf + intermediates) in PEM format
  /// </summary>
  public string Chain => $"{Certificate}{(IntermediateCertificate != null ? $"\n{IntermediateCertificate}" : "")}";

  /// <summary>
  /// Certificate expiration date (Unix timestamp)
  /// </summary>
  public int ExpiresAt { get; set; }

  /// <summary>
  /// Domain name(s) covered by this certificate
  /// </summary>
  public List<string> Domains { get; set; } = new();

  /// <summary>
  /// Server URL from which this certificate was obtained
  /// </summary>
  public string AcmeServerUrl { get; set; } = default!;
}
