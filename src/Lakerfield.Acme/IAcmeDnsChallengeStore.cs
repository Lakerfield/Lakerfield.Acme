using System;
using System.Collections.Generic;

namespace Lakerfield.Acme;

public interface IAcmeDnsChallengeStore
{
  void SetTxtRecord(string fqdn, string value, int? ttl = null, TimeSpan? validFor = null);

  void SetTxtRecord(string fqdn, IReadOnlyCollection<string> values, int? ttl = null, TimeSpan? validFor = null);

  bool RemoveRecord(string fqdn);

  bool TryGetLiveTxtRecord(string fqdn, out AcmeDnsTxtRecord record);

  IReadOnlyDictionary<string, AcmeDnsTxtRecord> Snapshot();
}
