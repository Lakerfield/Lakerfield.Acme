using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Lakerfield.Acme.Models;

namespace Lakerfield.Acme;

/// <summary>
/// Helper for JWS (JSON Web Signature) operations as per RFC 7515 and RFC 8555.
/// Implements ECDSA P-256 (ES256) signing without external dependencies.
/// </summary>
public static class JwtHelper
{
  private static readonly JsonSerializerOptions _jsonOptions = new()
  {
    WriteIndented = false,
    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
  };

  /// <summary>
  /// Computes base64url encoding of a byte array as per RFC 7515 §2.
  /// </summary>
  public static string Encode(byte[] data)
  {
    return Convert.ToBase64String(data)
      .TrimEnd('=')
      .Replace('+', '-')
      .Replace('/', '_');
  }

  /// <summary>
  /// Computes base64url encoding of a string (as UTF-8 bytes).
  /// </summary>
  public static string Encode(string payload) => Encode(Encoding.UTF8.GetBytes(payload));

  /// <summary>
  /// Decodes a base64url string back to bytes.
  /// </summary>
  public static byte[] Decode(string encoded)
  {
    string base64 = encoded
      .Replace('-', '+')
      .Replace('_', '/');

    int remainder = base64.Length % 4;
    if (remainder == 2)
      base64 += "==";
    else if (remainder == 3)
      base64 += "=";

    return Convert.FromBase64String(base64);
  }

  /// <summary>
  /// Computes the JWK thumbprint of an EC P-256 public key as per RFC 7638.
  /// The canonical JSON is: {"crv":"P-256","kty":"EC","x":"...","y":"..."} (keys sorted).
  /// </summary>
  public static string ComputeJwkThumbprint(ECDsa ecKey)
  {
    var parameters = ecKey.ExportParameters(includePrivateParameters: false);
    var x = Encode(parameters.Q.X!);
    var y = Encode(parameters.Q.Y!);

    // RFC 7638: canonical JSON with keys sorted lexicographically
    var canonicalJson = $"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}";
    var thumbprintBytes = SHA256.HashData(Encoding.UTF8.GetBytes(canonicalJson));
    return Encode(thumbprintBytes);
  }

  /// <summary>
  /// Creates an EcPublicKeyJwk object from an EC P-256 key.
  /// </summary>
  public static EcPublicKeyJwk ToPublicKeyJwk(ECDsa ecKey)
  {
    var parameters = ecKey.ExportParameters(includePrivateParameters: false);
    return new EcPublicKeyJwk
    {
      X = Encode(parameters.Q.X!),
      Y = Encode(parameters.Q.Y!),
    };
  }

  /// <summary>
  /// Computes the key authorization for an ACME challenge token as per RFC 8555 §8.1.
  /// keyAuthorization = token + "." + base64url(SHA256(canonicalJwkJson))
  /// </summary>
  public static string ComputeKeyAuthorization(string token, ECDsa ecKey)
  {
    var thumbprint = ComputeJwkThumbprint(ecKey);
    return $"{token}.{thumbprint}";
  }

  /// <summary>
  /// Computes the DNS-01 challenge value as per RFC 8555 §8.4.
  /// dns01Value = base64url(SHA256(keyAuthorization))
  /// </summary>
  public static string ComputeDns01Value(string keyAuthorization)
  {
    var digestBytes = SHA256.HashData(Encoding.UTF8.GetBytes(keyAuthorization));
    return Encode(digestBytes);
  }

  /// <summary>
  /// Creates a serialized JWS JSON string for an ACME POST request.
  /// Uses the JWK (public key) in the header — for new-account and revokeCert requests.
  /// </summary>
  public static string CreateJwsWithJwk(ECDsa ecKey, string nonce, string url, string? payloadJson)
  {
    var jwk = ToPublicKeyJwk(ecKey);
    var header = new JwsHeader
    {
      Alg = "ES256",
      Jwk = jwk,
      Nonce = nonce,
      Url = url,
    };
    return SignJws(ecKey, header, payloadJson);
  }

  /// <summary>
  /// Creates a serialized JWS JSON string for an ACME POST request.
  /// Uses the account URL as kid — for all requests after account creation.
  /// </summary>
  public static string CreateJwsWithKid(ECDsa ecKey, string accountUrl, string nonce, string url, string? payloadJson)
  {
    var header = new JwsHeader
    {
      Alg = "ES256",
      Kid = accountUrl,
      Nonce = nonce,
      Url = url,
    };
    return SignJws(ecKey, header, payloadJson);
  }

  /// <summary>
  /// Encodes the header JSON as per RFC 7515.
  /// </summary>
  public static string EncodeHeader(JwsHeaderExtensions header)
  {
    var json = JsonSerializer.Serialize(header, _jsonOptions);
    return Encode(Encoding.UTF8.GetBytes(json));
  }

  private static string SignJws(ECDsa ecKey, JwsHeader header, string? payloadJson)
  {
    var headerJson = JsonSerializer.Serialize(header, _jsonOptions);
    var protectedB64 = Encode(Encoding.UTF8.GetBytes(headerJson));

    // POST-as-GET uses empty payload; regular POSTs use base64url(json)
    var payloadB64 = payloadJson == null ? string.Empty : Encode(Encoding.UTF8.GetBytes(payloadJson));

    var signingInput = Encoding.UTF8.GetBytes($"{protectedB64}.{payloadB64}");

    // ECDSA P-256 signing with IEEE P1363 format (r || s, not DER ASN.1)
    var signatureBytes = ecKey.SignData(signingInput, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    var signatureB64 = Encode(signatureBytes);

    // JSON Flattened Serialization as per RFC 7515 §7.2.2 / RFC 8555 §6.2
    return JsonSerializer.Serialize(new
    {
      @protected = protectedB64,
      payload = payloadB64,
      signature = signatureB64,
    });
  }
}
