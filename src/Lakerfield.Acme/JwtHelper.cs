using System;
using System.Security.Cryptography;
using System.Text;
using Lakerfield.Acme.Models;

namespace Lakerfield.Acme;

/// <summary>
/// Helper voor base64url encoding en JWS signing.
/// </summary>
public static class JwtHelper
{
  /// <summary>
  /// Bereken base64url encoding van header JSON conform RFC 7515.
  /// </summary>
  public static string EncodeHeader(JwsHeaderExtensions header)
  {
    var json = System.Text.Json.JsonSerializer.Serialize(header, new System.Text.Json.JsonSerializerOptions
    {
      WriteIndented = false
    });

    return Encode(Encoding.UTF8.GetBytes(json));
  }

  /// <summary>
  /// Bereken base64url encoding van payload string.
  /// </summary>
  public static string Encode(string payload) => Encode(Encoding.UTF8.GetBytes(payload));

  /// <summary>
  /// Bereken base64url encoding van byte array (strip padding, URL-safe).
  /// </summary>
  public static string Encode(byte[] data)
  {
    return Convert.ToBase64String(data)
      .TrimEnd('=')
      .Replace('+', '-')
      .Replace('/', '_');
  }

  /// <summary>
  /// Decode base64url string back to bytes.
  /// </summary>
  public static byte[] Decode(string encoded)
  {
    // Convert back to standard base64 with padding
    string base64 = AddPadding(encoded);

    return Convert.FromBase64String(base64);
  }

  /// <summary>
  /// Add padding to base64url string.
  /// </summary>
  private static string AddPadding(string encoded)
  {
    int remainder = encoded.Length % 4;
    if (remainder == 0) return encoded;
    if (remainder == 1) throw new System.Exception("Invalid base64url encoding");
    if (remainder == 2) return encoded + "==";
    return encoded + "=";
  }

  /// <summary>
  /// Bereken ECDSA signature voor payload bytes.
  /// Voor nu placeholder - in productie met BouncyCastle.
  /// </summary>
  public static byte[] SignWithEcSha256(byte[] privateKeyBytes, byte[] payload)
  {
    // Placeholder implementation - use BouncyCastle for production
    throw new NotImplementedException("ECDSA P-256 signing requires BouncyCastle NuGet package");
  }

  /// <summary>
  /// Bereken signature voor string payload.
  /// </summary>
  public static byte[] SignWithEcSha256(string privateKeyBase64, string payload)
  {
    return SignWithEcSha256(Convert.FromBase64String(privateKeyBase64), Encoding.UTF8.GetBytes(payload));
  }

  /// <summary>
  /// Bereken ECDSA signature van JSON payload.
  /// </summary>
  public static byte[] SignWithEcSha256(string jsonPayload)
  {
    return SignWithEcSha256(Convert.FromBase64String("PLACEHOLDER"), Encoding.UTF8.GetBytes(jsonPayload));
  }

  /// <summary>
  /// Creer complete JWS string conform RFC 7515.
  /// Format: base64url(protected_header).base64url(payload).base64url(signature)
  /// </summary>
  public static string CreateJws(JwsHeaderExtensions header, string payload)
  {
    var protectedPart = EncodeHeader(header);
    var payloadPart = Encode(payload);

    // Placeholder signature for development - use real signing in production
    byte[] placeholderSignature = System.Text.Encoding.UTF8.GetBytes("PHOTOGRAPHY-012345");

    return
      $"{protectedPart}.{payloadPart}.base64url({Convert.ToBase64String(placeholderSignature).TrimEnd('=').Replace('+', '-').Replace('/', '_')})";
  }

  /// <summary>
  /// Placeholder JWS creation.
  /// </summary>
  public static string CreatePlaceholderJws(JwsHeaderExtensions header, string payload)
  {
    var protectedPart = EncodeHeader(header);
    var payloadPart = Encode(payload);

    // Simple placeholder - real implementation uses ECDSA signing
    return $"{protectedPart}.{payloadPart}.SIGNATURE_PLACEHOLDER";
  }
}
