using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Lakerfield.Acme.Models;

/// <summary>
/// ACME Directory meta object as per RFC 8555 §7.1.1
/// </summary>
public class AcmeDirectoryMeta
{
  /// <summary>
  /// Hostnames that the ACME server recognizes as authoritative for CAA records.
  /// </summary>
  [JsonPropertyName("caaIdentities")]
  public List<string>? CaaIdentities { get; set; }

  /// <summary>
  /// Certificate profiles supported by this ACME server.
  /// Keys are profile names (e.g. "classic", "shortlived"), values are informational URLs.
  /// </summary>
  [JsonPropertyName("profiles")]
  public Dictionary<string, string>? Profiles { get; set; }

  /// <summary>
  /// URL of the current Terms of Service document.
  /// </summary>
  [JsonPropertyName("termsOfService")]
  public string? TermsOfService { get; set; }

  /// <summary>
  /// URL of a website providing more information about the ACME server.
  /// </summary>
  [JsonPropertyName("website")]
  public string? Website { get; set; }
}
