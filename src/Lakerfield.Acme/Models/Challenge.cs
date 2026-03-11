using System.Text.Json.Serialization;

namespace Lakerfield.Acme.Models;

/// <summary>
/// ACME Challenge object as per RFC 8555 §7.1.5
/// </summary>
public class Challenge
{
  /// <summary>
  /// Validation method: "http-01", "dns-01", or "tls-alpn-01"
  /// </summary>
  [JsonPropertyName("type")]
  public string Type { get; set; } = default!;

  /// <summary>
  /// Status: "pending", "processing", "valid", or "invalid"
  /// </summary>
  [JsonPropertyName("status")]
  public string Status { get; set; } = "pending";

  /// <summary>
  /// URL to POST to trigger validation
  /// </summary>
  [JsonPropertyName("url")]
  public string Url { get; set; } = default!;

  /// <summary>
  /// Token value used to construct the key authorization
  /// </summary>
  [JsonPropertyName("token")]
  public string? Token { get; set; }

  /// <summary>
  /// Error details if the challenge failed
  /// </summary>
  [JsonPropertyName("error")]
  public AcmeError? AcmeError { get; set; }

  /// <summary>
  /// Convenience accessor for error message
  /// </summary>
  [JsonIgnore]
  public string? ErrorMessage => AcmeError?.Detail;

  /// <summary>
  /// Key authorization value (token + "." + JWK thumbprint), computed locally
  /// </summary>
  public string? KeyAuthorization { get; set; }

  /// <summary>
  /// Validation domain for DNS-01 challenges (e.g., _acme-challenge.example.com)
  /// </summary>
  public string? ValidationDomain { get; set; }
}

/// <summary>
/// Challenge status enumeration as per RFC 8555
/// </summary>
public enum ChallengeStatus
{
  Pending,
  Processing,
  Valid,
  Invalid,
  Ready
}

/// <summary>
/// Type of ACME challenge.
/// </summary>
public enum ChallengeType
{
  Http01,
  Dns01,
  TlsAlpn01
}
