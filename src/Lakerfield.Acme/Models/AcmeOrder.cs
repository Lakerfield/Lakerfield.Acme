using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Lakerfield.Acme.Models;

/// <summary>
/// ACME Order object conform RFC 8555 §7.1.3
/// </summary>
public class AcmeOrder
{
  /// <summary>
  /// Order status: "pending", "ready", "processing", "valid", or "invalid"
  /// </summary>
  [JsonPropertyName("status")]
  public string Status { get; set; } = default!;

  /// <summary>
  /// Expiry timestamp (RFC 3339 format)
  /// </summary>
  [JsonPropertyName("expires")]
  public string? Expires { get; set; }

  /// <summary>
  /// List of domain identifiers covered by this order
  /// </summary>
  [JsonPropertyName("identifiers")]
  public List<AcmeIdentifier> Identifiers { get; set; } = new();

  /// <summary>
  /// URLs of the authorizations that need to be satisfied
  /// </summary>
  [JsonPropertyName("authorizations")]
  public List<string> Authorizations { get; set; } = new();

  /// <summary>
  /// URL to submit CSR to finalize the order
  /// </summary>
  [JsonPropertyName("finalize")]
  public string Finalize { get; set; } = default!;

  /// <summary>
  /// URL to download the issued certificate (available after order is "valid")
  /// </summary>
  [JsonPropertyName("certificate")]
  public string? Certificate { get; set; }

  /// <summary>
  /// Order URL (from Location header or request URL)
  /// </summary>
  public string? Url { get; set; }
}
