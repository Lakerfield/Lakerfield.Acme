using System.Text.Json.Serialization;

namespace Lakerfield.Acme.Models;

/// <summary>
/// ACME Directory object as per RFC 8555 §7.1.1
/// </summary>
public class AcmeDirectory
{
  /// <summary>
  /// URL to fetch a new nonce (HEAD or GET)
  /// </summary>
  [JsonPropertyName("newNonce")]
  public string NewNonce { get; set; } = default!;

  /// <summary>
  /// URL to create a new account
  /// </summary>
  [JsonPropertyName("newAccount")]
  public string NewAccount { get; set; } = default!;

  /// <summary>
  /// URL to create a new order
  /// </summary>
  [JsonPropertyName("newOrder")]
  public string NewOrder { get; set; } = default!;

  /// <summary>
  /// URL to revoke a certificate
  /// </summary>
  [JsonPropertyName("revokeCert")]
  public string RevokeCert { get; set; } = default!;

  /// <summary>
  /// URL to change account key
  /// </summary>
  [JsonPropertyName("keyChange")]
  public string? KeyChange { get; set; }

  /// <summary>
  /// Optional metadata about the ACME server (terms of service, profiles, CAA identities, etc.)
  /// </summary>
  [JsonPropertyName("meta")]
  public AcmeDirectoryMeta? Meta { get; set; }
}
