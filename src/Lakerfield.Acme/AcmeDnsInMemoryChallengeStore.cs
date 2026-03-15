using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Lakerfield.Acme;

public sealed class AcmeDnsInMemoryChallengeStore : IAcmeDnsChallengeStore
{
  private readonly ConcurrentDictionary<string, AcmeDnsTxtRecord> _records =
      new(StringComparer.OrdinalIgnoreCase);

  private readonly AcmeDnsServerOptions _options;

  public AcmeDnsInMemoryChallengeStore(Microsoft.Extensions.Options.IOptions<AcmeDnsServerOptions> options)
  {
    _options = options.Value;
  }

  public void SetTxtRecord(string fqdn, string value, int? ttl = null, TimeSpan? validFor = null)
      => SetTxtRecord(fqdn, new[] { value }, ttl, validFor);

  public void SetTxtRecord(string fqdn, IReadOnlyCollection<string> values, int? ttl = null, TimeSpan? validFor = null)
  {
    if (string.IsNullOrWhiteSpace(fqdn))
      throw new ArgumentException("FQDN is required.", nameof(fqdn));

    if (values is null || values.Count == 0)
      throw new ArgumentException("At least one TXT value is required.", nameof(values));

    fqdn = NormalizeName(fqdn);

    if (!IsInZone(fqdn, _options.ZoneName))
      throw new InvalidOperationException($"'{fqdn}' is not in zone '{_options.ZoneName}'.");

    var distinctValues = values
        .Where(v => !string.IsNullOrWhiteSpace(v))
        .Distinct(StringComparer.Ordinal)
        .ToArray();

    if (distinctValues.Length == 0)
      throw new ArgumentException("At least one non-empty TXT value is required.", nameof(values));

    foreach (var value in distinctValues)
    {
      var bytes = Encoding.UTF8.GetBytes(value);
      if (bytes.Length > 255)
        throw new ArgumentException($"TXT value is larger than 255 bytes: '{value}'.", nameof(values));
    }

    _records[fqdn] = new AcmeDnsTxtRecord(
        ttl ?? _options.DefaultTtl,
        validFor is null ? null : DateTimeOffset.UtcNow.Add(validFor.Value),
        distinctValues);
  }

  public bool RemoveRecord(string fqdn)
  {
    if (string.IsNullOrWhiteSpace(fqdn))
      return false;

    return _records.TryRemove(NormalizeName(fqdn), out _);
  }

  public bool TryGetLiveTxtRecord(string fqdn, out AcmeDnsTxtRecord record)
  {
    fqdn = NormalizeName(fqdn);

    if (_records.TryGetValue(fqdn, out record!))
    {
      if (record.ExpiresAtUtc is null || record.ExpiresAtUtc > DateTimeOffset.UtcNow)
        return true;

      _records.TryRemove(fqdn, out _);
    }

    record = null!;
    return false;
  }

  public IReadOnlyDictionary<string, AcmeDnsTxtRecord> Snapshot()
  {
    var result = new Dictionary<string, AcmeDnsTxtRecord>(StringComparer.OrdinalIgnoreCase);

    foreach (var kvp in _records)
    {
      if (TryGetLiveTxtRecord(kvp.Key, out var record))
        result[kvp.Key] = record;
    }

    return result;
  }

  private static string NormalizeName(string name)
      => name.Trim().TrimEnd('.');

  private static bool IsInZone(string fqdn, string zoneName)
  {
    zoneName = NormalizeName(zoneName);

    return fqdn.Equals(zoneName, StringComparison.OrdinalIgnoreCase)
        || fqdn.EndsWith("." + zoneName, StringComparison.OrdinalIgnoreCase);
  }
}
