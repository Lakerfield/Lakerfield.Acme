using System.Text.Json.Serialization;

namespace Lakerfield.Acme.Models;

/// <summary>
/// JWS Protected Header as per RFC 7515 and ACME specification (RFC 8555 §6.2)
/// </summary>
public class JwsHeader
{
  /// <summary>
  /// Algorithm used for signing: "ES256" (ECDSA P-256 + SHA-256)
  /// </summary>
  [JsonPropertyName("alg")]
  public string Alg { get; set; } = "ES256";

  /// <summary>
  /// JSON Web Key (jwk) - used for new-account and revokeCert requests
  /// Only one of Jwk or Kid should be set.
  /// </summary>
  [JsonPropertyName("jwk")]
  [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
  public object? Jwk { get; set; }

  /// <summary>
  /// Key ID (kid) - the account URL, used for requests after account creation.
  /// Only one of Jwk or Kid should be set.
  /// </summary>
  [JsonPropertyName("kid")]
  [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
  public string? Kid { get; set; }

  /// <summary>
  /// Nonce from ACME server (Replay-Nonce header, required for all POST requests)
  /// </summary>
  [JsonPropertyName("nonce")]
  public string Nonce { get; set; } = default!;

  /// <summary>
  /// URL of the endpoint being called (required for all POST requests)
  /// </summary>
  [JsonPropertyName("url")]
  public string Url { get; set; } = default!;
}

/// <summary>
/// JWK (JSON Web Key) for EC P-256 public key as per RFC 7517
/// </summary>
public class EcPublicKeyJwk
{
  [JsonPropertyName("kty")]
  public string Kty { get; set; } = "EC";

  [JsonPropertyName("crv")]
  public string Crv { get; set; } = "P-256";

  [JsonPropertyName("x")]
  public string X { get; set; } = default!;

  [JsonPropertyName("y")]
  public string Y { get; set; } = default!;
}

/// <summary>
/// Legacy JWS header extensions class - kept for compatibility.
/// </summary>
public class JwsHeaderExtensions
{
  public string Alg { get; set; } = "ES256";
  public string Kid { get; set; } = default!;
  public string? Nonce { get; set; }
  public string Url { get; set; } = default!;
}
