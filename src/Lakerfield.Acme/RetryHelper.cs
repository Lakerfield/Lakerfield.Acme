using System.Collections.Generic;

namespace Lakerfield.Acme.Models;

/// <summary>
/// Retry Policy helper conform best practices.
/// </summary>
public static class RetryHelper
{
  /// <summary>
  /// Default retry config voor ACME calls.
  /// </summary>
  public static AcmeRetryConfig DefaultRetryPolicy { get; } = new()
  {
    MaxAttempts = 3,
    InitialDelaySeconds = 2,
    MaxDelaySeconds = 30,
    ExponentialBase = 2,
    AllowedHttpStatusCodes = new List<int> { 502, 503, 504 }, // Server errors only
    TimeoutSeconds = 10
  };
}
