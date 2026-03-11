using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Lakerfield.Acme.Models;

/// <summary>
/// ACME Authorization object conform RFC 8555 §7.1.4
/// </summary>
public class Authorization
{
  /// <summary>
  /// The domain identifier being authorized
  /// </summary>
  [JsonPropertyName("identifier")]
  public AcmeIdentifier? IdentifierObj { get; set; }

  /// <summary>
  /// Domain name (convenience accessor for IdentifierObj.Value)
  /// </summary>
  public string Identifier => IdentifierObj?.Value ?? string.Empty;

  /// <summary>
  /// Status: "pending", "valid", "invalid", "deactivated", "expired", or "revoked"
  /// </summary>
  [JsonPropertyName("status")]
  public string Status { get; set; } = "pending";

  /// <summary>
  /// Expiry timestamp (RFC 3339 format)
  /// </summary>
  [JsonPropertyName("expires")]
  public string? Expires { get; set; }

  /// <summary>
  /// List of challenges associated with this authorization
  /// </summary>
  [JsonPropertyName("challenges")]
  public List<Challenge> Challenges { get; set; } = new();

  /// <summary>
  /// Whether this is a wildcard authorization
  /// </summary>
  [JsonPropertyName("wildcard")]
  public bool? Wildcard { get; set; }

  /// <summary>
  /// Authorization URL (set after fetching)
  /// </summary>
  public string? Url { get; set; }
}
