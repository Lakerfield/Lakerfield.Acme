using System.Collections.Generic;

namespace Lakerfield.Acme.Models;

/// <summary>
/// ACME Challenge object conform RFC 8555 §3 and §6
/// </summary>
public class Challenge
{
  /// <summary>
  /// Unique identifier for this challenge
  /// </summary>
  public string Id { get; set; } = default!;

  /// <summary>
  /// Validation method: "http-01", "dns-01", "tls-alpn-01"
  /// </summary>
  public string Type { get; set; } = default!;

  /// <summary>
  /// Status: "pending", "processing", "valid", "invalid", or "ready"
  /// </summary>
  public string Status { get; set; } = "pending";

  /// <summary>
  /// URL to check for challenge response (HTTP-01 only)
  /// </summary>
  public string Url { get; set; } = default!;

  /// <summary>
  /// Token value for HTTP-01 or DNS-01 challenges
  /// </summary>
  public string? Token { get; set; }

  /// <summary>
  /// Value to provision (HTTP response body or DNS TXT record)
  /// </summary>
  public string? ExpectedValue { get; set; }

  /// <summary>
  /// Actual value returned by the server after validation
  /// </summary>
  public string? ValidationRecord { get; set; }

  /// <summary>
  /// Error description if challenge failed (optional in response)
  /// </summary>
  public string? Error { get; set; }

  /// <summary>
  /// URL to check challenge status
  /// </summary>
  public string UrlPath { get; set; } = default!;

  /// <summary>
  /// Validation domain for DNS challenges (e.g., _acme-challenge.example.com)
  /// </summary>
  public string? ValidationDomain { get; set; }

  /// <summary>
  /// For tls-alpn-01: list of protocol names the server should negotiate
  /// </summary>
  public List<string>? AlpnProtocols { get; set; } = new() { "acme-tls/1" };
}

/// <summary>
/// Challenge status enumeration conform RFC 8555
/// </summary>
public enum ChallengeStatus
{
  Pending,
  Processing,
  Valid,
  Invalid,
  Ready
}
