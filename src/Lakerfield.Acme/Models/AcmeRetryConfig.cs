using System.Collections.Generic;
using System.Net.Http.Headers;
using System.Text.Json;

namespace Lakerfield.Acme.Models;

/// <summary>
/// Retry configuratie voor ACME calls.
/// </summary>
public class AcmeRetryConfig
{
  /// <summary>
  /// Maximum aantal pogingen per request.
  /// </summary>
  public int MaxAttempts { get; set; } = 3;

  /// <summary>
  /// Initial delay tussen pogingen (in seconden).
  /// </summary>
  public int InitialDelaySeconds { get; set; } = 2;

  /// <summary>
  /// Maximum delay tussen pogingen (exponential backoff).
  /// </summary>
  public int MaxDelaySeconds { get; set; } = 30;

  /// <summary>
  /// Base voor exponential backoff: delay * base^(attempt-1)
  /// </summary>
  public double ExponentialBase { get; set; } = 2;

  /// <summary>
  /// HTTP status codes die opnieuw geprobeerd worden.
  /// </summary>
  public List<int> AllowedHttpStatusCodes { get; set; } = new() { 502, 503, 504 };

  /// <summary>
  /// Timeout per attempt in seconden.
  /// </summary>
  public int TimeoutSeconds { get; set; } = 10;
}
