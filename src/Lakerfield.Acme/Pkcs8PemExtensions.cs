using System;
using System.Security.Cryptography;

namespace Lakerfield.Acme;

public static class Pkcs8PemExtensions
{
  private const string PrivateKeyPemLabel = "PRIVATE KEY";

  public static string ToPem(this byte[] pkcs8Der)
  {
    ArgumentNullException.ThrowIfNull(pkcs8Der);
    return PemEncoding.WriteString(PrivateKeyPemLabel, pkcs8Der);
  }

  public static byte[] FromPem(this string pem)
  {
    ArgumentException.ThrowIfNullOrWhiteSpace(pem);

    PemFields fields = PemEncoding.Find(pem);
    ReadOnlySpan<char> pemSpan = pem.AsSpan();

    string label = pemSpan[fields.Label].ToString();
    if (!string.Equals(label, PrivateKeyPemLabel, StringComparison.Ordinal))
      throw new InvalidOperationException(
        $"Expected PEM label '{PrivateKeyPemLabel}', but found '{label}'.");

    return Convert.FromBase64String(pemSpan[fields.Base64Data].ToString());
  }
}
