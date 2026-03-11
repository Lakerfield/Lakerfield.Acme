namespace Lakerfield.Acme.Models;

/// <summary>
/// ACME Account object conform RFC 8555 §6
/// </summary>
public class Account
{
  /// <summary>
  /// Unique identifier for this account
  /// </summary>
  public string Id { get; set; } = default!;

  /// <summary>
  /// Email address for notifications (optional, may be restricted)
  /// </summary>
  public string? Contact { get; set; }

  /// <summary>
  /// Status: "valid", "invalid", or "deactivated"
  /// </summary>
  public string Status { get; set; } = "valid";

  /// <summary>
  /// Unix timestamp when the account was created
  /// </summary>
  public int CreatedAt { get; set; }

  /// <summary>
  /// Public key JWK for this account
  /// </summary>
  public string Key { get; set; } = default!;

  /// <summary>
  /// True if the account is being used for pending authorizations
  /// </summary>
  public bool? Enabled { get; set; }

  /// <summary>
  /// Directory URL for this account
  /// </summary>
  public string Url { get; set; } = default!;
}
