using System.Collections.Generic;
using System.Net.Http.Headers;
using System.Text.Json;

namespace Lakerfield.Acme.Models;

/// <summary>
/// Retry configuration for ACME calls.
/// </summary>
public class AcmeRetryConfig
{
  /// <summary>
  /// Maximum number of attempts per request.
  /// </summary>
  public int MaxAttempts { get; set; } = 3;

  /// <summary>
  /// Initial delay between attempts (in seconds).
  /// </summary>
  public int InitialDelaySeconds { get; set; } = 2;

  /// <summary>
  /// Maximum delay between attempts (exponential backoff).
  /// </summary>
  public int MaxDelaySeconds { get; set; } = 30;

  /// <summary>
  /// Base for exponential backoff: delay * base^(attempt-1)
  /// </summary>
  public double ExponentialBase { get; set; } = 2;

  /// <summary>
  /// HTTP status codes that will be retried.
  /// </summary>
  public List<int> AllowedHttpStatusCodes { get; set; } = new() { 502, 503, 504 };

  /// <summary>
  /// Timeout per attempt in seconds.
  /// </summary>
  public int TimeoutSeconds { get; set; } = 10;
}
