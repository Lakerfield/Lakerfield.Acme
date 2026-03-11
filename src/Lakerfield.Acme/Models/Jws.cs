using System.Text.Json.Serialization;

namespace Lakerfield.Acme.Models;

/// <summary>
/// JWS (JSON Web Signature) conform RFC 7515 and ACME specification
/// </summary>
public class Jws
{
  /// <summary>
  /// Base64url-encoded protected header (alg, kid, nonce, url)
  /// </summary>
  public string Protected { get; set; } = default!;

  /// <summary>
  /// Base64url-encoded payload
  /// </summary>
  public string Payload { get; set; } = default!;

  /// <summary>
  /// Base64url-encoded signature
  /// </summary>
  public string Signature { get; set; } = default!;

  /// <summary>
  /// Complete JWS as a single string (Protected + "." + Payload + "." + Signature)
  /// </summary>
  public string ToFullString() => $"{Protected}.{Payload}.{Signature}";
}

/// <summary>
/// JWOS (JSON Web Object Signing) - for protected headers with pre-computed signature
/// </summary>
public class Jwos
{
  /// <summary>
  /// Base64url-encoded protected header
  /// </summary>
  public string Protected { get; set; } = default!;

  /// <summary>
  /// Base64url-encoded payload
  /// </summary>
  public string Payload { get; set; } = default!;

  /// <summary>
  /// Base64url-encoded signature (may be pre-computed or empty for later signing)
  /// </summary>
  public string? Signature { get; set; }
}
