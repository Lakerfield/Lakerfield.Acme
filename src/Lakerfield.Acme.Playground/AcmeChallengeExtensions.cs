using System.Collections.Concurrent;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Lakerfield.Acme.Playground;

/// <summary>
/// Stores HTTP-01 ACME challenge tokens and their corresponding key authorizations
/// so that the minimal web app can serve them on demand.
/// </summary>
public class AcmeChallengeTokenStore
{
  private readonly ConcurrentDictionary<string, string> _tokens = new();

  /// <summary>
  /// Registers a token/key-authorization pair so that it can be served over HTTP.
  /// </summary>
  public void AddToken(string token, string keyAuthorization)
    => _tokens[token] = keyAuthorization;

  /// <summary>
  /// Looks up the key authorization value for a given token.
  /// </summary>
  public bool TryGetToken(string token, out string keyAuthorization)
  {
    if (_tokens.TryGetValue(token, out var value))
    {
      keyAuthorization = value;
      return true;
    }
    keyAuthorization = string.Empty;
    return false;
  }

  /// <summary>
  /// Removes a token once the challenge has been validated.
  /// </summary>
  public void RemoveToken(string token)
    => _tokens.TryRemove(token, out _);
}

/// <summary>
/// Extension methods for hosting ACME HTTP-01 challenges in a minimal ASP.NET Core web app.
/// </summary>
public static class AcmeChallengeExtensions
{
  /// <summary>
  /// Registers the <see cref="AcmeChallengeTokenStore"/> as a singleton service.
  /// Call this on the <see cref="IServiceCollection"/> before building the app.
  /// </summary>
  public static IServiceCollection AddAcmeHttp01Challenge(this IServiceCollection services)
  {
    services.AddSingleton<AcmeChallengeTokenStore>();
    return services;
  }

  /// <summary>
  /// Maps the ACME HTTP-01 challenge endpoint at
  /// <c>/.well-known/acme-challenge/{token}</c>.
  /// The endpoint returns the key-authorization value that was registered via
  /// <see cref="AcmeChallengeTokenStore.AddToken"/>.
  /// </summary>
  /// <remarks>
  /// In production the web app must listen on port 80, because the ACME server
  /// always contacts the domain on port 80 for HTTP-01 validation.
  /// </remarks>
  public static WebApplication UseAcmeHttp01Challenge(this WebApplication app)
  {
    app.MapGet(
      "/.well-known/acme-challenge/{token}",
      (AcmeChallengeTokenStore store, string token) =>
      {
        // Validate token: ACME tokens are base64url-encoded and may only contain
        // alphanumeric characters, '-', and '_' (RFC 8555 §8.3).
        if (!IsValidAcmeToken(token))
          return Results.BadRequest();

        return store.TryGetToken(token, out var keyAuthorization)
          ? Results.Text(keyAuthorization)
          : Results.NotFound();
      });

    return app;
  }

  /// <summary>
  /// Returns <see langword="true"/> when <paramref name="token"/> consists solely
  /// of base64url characters (A–Z, a–z, 0–9, '-', '_'), as required by RFC 8555.
  /// </summary>
  private static bool IsValidAcmeToken(string token)
  {
    if (string.IsNullOrEmpty(token))
      return false;

    foreach (var c in token)
    {
      if (!char.IsAsciiLetterOrDigit(c) && c != '-' && c != '_')
        return false;
    }

    return true;
  }
}
