using System;

namespace Lakerfield.Acme;

public sealed record AcmeDnsTxtRecord(
  int Ttl,
  DateTimeOffset? ExpiresAtUtc,
  string[] Values);
