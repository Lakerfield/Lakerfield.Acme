using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Lakerfield.Acme.Models;

namespace Lakerfield.Acme;

/// <summary>
/// Helper voor JWS (JSON Web Signature) operations conform RFC 7515 en RFC 8555.
/// Implementeert ECDSA P-256 (ES256) signing zonder externe dependencies.
/// </summary>
public static class JwtHelper
{
  private static readonly JsonSerializerOptions _jsonOptions = new()
  {
    WriteIndented = false,
    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
  };

  /// <summary>
  /// Bereken base64url encoding van byte array conform RFC 7515 §2.
  /// </summary>
  public static string Encode(byte[] data)
  {
    return Convert.ToBase64String(data)
      .TrimEnd('=')
      .Replace('+', '-')
      .Replace('/', '_');
  }

  /// <summary>
  /// Bereken base64url encoding van string (als UTF-8 bytes).
  /// </summary>
  public static string Encode(string payload) => Encode(Encoding.UTF8.GetBytes(payload));

  /// <summary>
  /// Decode base64url string terug naar bytes.
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
  /// Bereken de JWK thumbprint van een EC P-256 public key conform RFC 7638.
  /// De canonical JSON is: {"crv":"P-256","kty":"EC","x":"...","y":"..."} (keys gesorteerd).
  /// </summary>
  public static string ComputeJwkThumbprint(ECDsa ecKey)
  {
    var parameters = ecKey.ExportParameters(includePrivateParameters: false);
    var x = Encode(parameters.Q.X!);
    var y = Encode(parameters.Q.Y!);

    // RFC 7638: canonical JSON met keys lexicografisch gesorteerd
    var canonicalJson = $"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}";
    var thumbprintBytes = SHA256.HashData(Encoding.UTF8.GetBytes(canonicalJson));
    return Encode(thumbprintBytes);
  }

  /// <summary>
  /// Maak een EcPublicKeyJwk object van een EC P-256 key.
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
  /// Bereken de key authorization voor een ACME challenge token conform RFC 8555 §8.1.
  /// keyAuthorization = token + "." + base64url(SHA256(canonicalJwkJson))
  /// </summary>
  public static string ComputeKeyAuthorization(string token, ECDsa ecKey)
  {
    var thumbprint = ComputeJwkThumbprint(ecKey);
    return $"{token}.{thumbprint}";
  }

  /// <summary>
  /// Bereken de DNS-01 challenge waarde conform RFC 8555 §8.4.
  /// dns01Value = base64url(SHA256(keyAuthorization))
  /// </summary>
  public static string ComputeDns01Value(string keyAuthorization)
  {
    var digestBytes = SHA256.HashData(Encoding.UTF8.GetBytes(keyAuthorization));
    return Encode(digestBytes);
  }

  /// <summary>
  /// Maak een geserialiseerde JWS JSON string voor een ACME POST request.
  /// Gebruikt de JWK (public key) in de header - voor new-account en revokeCert.
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
  /// Maak een geserialiseerde JWS JSON string voor een ACME POST request.
  /// Gebruikt het account URL als kid - voor alle requests na account aanmaken.
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
  /// Bereken header JSON conform RFC 7515.
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

    // POST-as-GET gebruikt leeg payload; reguliere POSTs gebruiken base64url(json)
    var payloadB64 = payloadJson == null ? string.Empty : Encode(Encoding.UTF8.GetBytes(payloadJson));

    var signingInput = Encoding.UTF8.GetBytes($"{protectedB64}.{payloadB64}");

    // ECDSA P-256 signing met IEEE P1363 formaat (r || s, geen DER ASN.1)
    var signatureBytes = ecKey.SignData(signingInput, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    var signatureB64 = Encode(signatureBytes);

    // JSON FlattenedSerialization conform RFC 7515 §7.2.2 / RFC 8555 §6.2
    return JsonSerializer.Serialize(new
    {
      @protected = protectedB64,
      payload = payloadB64,
      signature = signatureB64,
    });
  }
}
