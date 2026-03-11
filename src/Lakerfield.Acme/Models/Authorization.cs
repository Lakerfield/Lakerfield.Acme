using System.Collections.Generic;

namespace Lakerfield.Acme.Models;

/// <summary>
/// ACME Authorization object conform RFC 8555 §4
/// </summary>
public class Authorization
{
  /// <summary>
  /// Unique identifier for this authorization
  /// </summary>
  public string Id { get; set; } = default!;

  /// <summary>
  /// The domain name being validated (e.g., "example.com", "www.example.com")
  /// </summary>
  public string Identifier { get; set; } = default!;

  /// <summary>
  /// Whether the authorization is being used for pending challenges
  /// </summary>
  public bool? IsPrimary { get; set; }

  /// <summary>
  /// Status: "valid", "invalid", or "pending"
  /// </summary>
  public string Status { get; set; } = "pending";

  /// <summary>
  /// The challenge type to use for validation
  /// Options: "http-01", "dns-01", "tls-alpn-01"
  /// </summary>
  public string[]? ChallengeType { get; set; }

  /// <summary>
  /// List of challenges associated with this authorization
  /// </summary>
  public List<Challenge> Challenges { get; set; } = new();

  /// <summary>
  /// URL to check this authorization's status
  /// </summary>
  public string UrlPath { get; set; } = default!;
}
