using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Lakerfield.Acme.Models;

/// <summary>
/// ACME Account object conform RFC 8555 §7.1.2
/// </summary>
public class Account
{
  /// <summary>
  /// Unique identifier for this account (local, not from ACME server)
  /// </summary>
  public string Id { get; set; } = default!;

  /// <summary>
  /// Contact email addresses (e.g., ["mailto:admin@example.com"])
  /// </summary>
  [JsonPropertyName("contact")]
  public List<string>? Contact { get; set; }

  /// <summary>
  /// Status: "valid", "deactivated", or "revoked"
  /// </summary>
  [JsonPropertyName("status")]
  public string Status { get; set; } = "valid";

  /// <summary>
  /// Whether the client has agreed to the terms of service
  /// </summary>
  [JsonPropertyName("termsOfServiceAgreed")]
  public bool? TermsOfServiceAgreed { get; set; }

  /// <summary>
  /// URL to list the orders for this account
  /// </summary>
  [JsonPropertyName("orders")]
  public string? Orders { get; set; }

  /// <summary>
  /// Public key JWK for this account (returned by server)
  /// </summary>
  [JsonPropertyName("key")]
  public object? Key { get; set; }

  /// <summary>
  /// Account URL (from Location header, used as kid in subsequent requests)
  /// </summary>
  public string Url { get; set; } = default!;
}
