namespace Lakerfield.Acme.Models;

/// <summary>
/// JWS Header extensions conform RFC 7515 and ACME specification
/// </summary>
public class JwsHeaderExtensions
{
  /// <summary>
  /// Algorithm used for signing: "HS256", "RS256", or "ES256"
  /// </summary>
  public string Alg { get; set; } = "ES256";

  /// <summary>
  /// Key ID (kid) - typically the account URL
  /// </summary>
  public string Kid { get; set; } = default!;

  /// <summary>
  /// Nonce from ACME server (ACME v2 requirement)
  /// </summary>
  public string? Nonce { get; set; }

  /// <summary>
  /// URL of the resource being signed
  /// </summary>
  public string Url { get; set; } = default!;
}

/// <summary>
/// ACME Client Error conform RFC 8555 Appendix C
/// </summary>
public class AcmeError
{
  /// <summary>
  /// Error type identifier
  /// </summary>
  public string Type { get; set; } = default!;

  /// <summary>
  /// Human-readable error message
  /// </summary>
  public string Detail { get; set; } = default!;

  /// <summary>
  /// Optional additional context
  /// </summary>
  public string? Title { get; set; }
}
