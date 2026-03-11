using System.Text.Json.Serialization;

namespace Lakerfield.Acme.Models;

/// <summary>
/// ACME Identifier object as per RFC 8555 §9.7.7
/// </summary>
public class AcmeIdentifier
{
  /// <summary>
  /// Identifier type (always "dns" for domain name certificates)
  /// </summary>
  [JsonPropertyName("type")]
  public string Type { get; set; } = "dns";

  /// <summary>
  /// Domain name value (e.g., "example.com" or "*.example.com" for wildcards)
  /// </summary>
  [JsonPropertyName("value")]
  public string Value { get; set; } = default!;
}
