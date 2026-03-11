using System.Text.Json;

namespace Lakerfield.Acme;

/// <summary>
/// ACME exception voor errors in ACME protocol.
/// </summary>
public class AcmeException : System.Exception
{
  /// <summary>
  /// Parse ACME error response tot AcmeError object.
  /// </summary>
  public AcmeError? Error => JsonSerializer.Deserialize<AcmeError>(Message);

  public AcmeException(string message) : base(message)
  {
  }

  public AcmeException(string message, System.Exception inner) : base(message, inner)
  {
  }
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
