using System;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace Lakerfield.Acme;

public static class AcmeDnsNameHelper
{
  private static readonly IdnMapping Idn = new();

  /// <summary>
  /// Converts a domain name to a deterministic DNS-safe prefix.
  ///
  /// Examples:
  /// example.com         -> example-com
  /// *.example.com       -> example-com
  /// api.example.com     -> api-example-com
  /// *.api.example.com   -> api-example-com
  /// bücher.de           -> xn--bcher-kva-de
  /// </summary>
  public static string DomainToPrefix(string domain)
  {
    if (string.IsNullOrWhiteSpace(domain))
      throw new ArgumentException("Domain is required.", nameof(domain));
    
    domain = domain.Trim();

    // Strip wildcard marker if present.
    if (domain.StartsWith("*.", StringComparison.Ordinal))
      domain = domain[2..];

    // Remove trailing dot if the caller passed a FQDN.
    domain = domain.TrimEnd('.');

    if (domain.Length == 0)
      throw new ArgumentException("Domain is invalid.", nameof(domain));

    // Convert Unicode domain names to ASCII punycode.
    domain = Idn.GetAscii(domain).ToLowerInvariant();

    if (!IsValidDnsName(domain))
      throw new ArgumentException($"Domain '{domain}' is not a valid DNS name.", nameof(domain));

    // Replace dots with dashes to make a single DNS-label-safe prefix.
    var prefix = domain.Replace('.', '-');

    // Defense in depth: only keep [a-z0-9-]
    prefix = Regex.Replace(prefix, @"[^a-z0-9-]", "-");
    prefix = Regex.Replace(prefix, @"-+", "-").Trim('-');

    return EnsureDnsLabelLength(prefix);
  }

  private static bool IsValidDnsName(string domain)
  {
    if (domain.Length > 253)
      return false;

    var labels = domain.Split('.', StringSplitOptions.RemoveEmptyEntries);
    if (labels.Length == 0)
      return false;

    foreach (var label in labels)
    {
      if (label.Length is < 1 or > 63)
        return false;

      if (label.StartsWith('-') || label.EndsWith('-'))
        return false;

      foreach (var ch in label)
      {
        var ok = (ch >= 'a' && ch <= 'z') ||
                 (ch >= '0' && ch <= '9') ||
                 ch == '-';

        if (!ok)
          return false;
      }
    }

    return true;
  }

  private static string EnsureDnsLabelLength(string value)
  {
    if (value.Length <= 63)
      return value;

    var hash = Fnv1a32Hex(value);
    var keep = 63 - 1 - hash.Length; // "-" + hash
    return value[..keep].TrimEnd('-') + "-" + hash;
  }

  private static string Fnv1a32Hex(string input)
  {
    unchecked
    {
      const uint offset = 2166136261;
      const uint prime = 16777619;

      uint hash = offset;
      foreach (var ch in Encoding.UTF8.GetBytes(input))
      {
        hash ^= ch;
        hash *= prime;
      }

      return hash.ToString("x8");
    }
  }
}
