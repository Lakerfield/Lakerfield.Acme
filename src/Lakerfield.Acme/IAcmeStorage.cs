using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Lakerfield.Acme.Models;

namespace Lakerfield.Acme;

/// <summary>
/// Storage interface voor ACME credentials en validation data.
/// Implementatie kan MongoDB, disk, of andere storage gebruiken.
/// </summary>
public interface IAcmeStorage : IDisposable
{
  /// <summary>
  /// Haal of creeer een account met de opgegeven private key.
  /// </summary>
  /// <param name="keyJwk">Base64Url-encoded private key JWK</param>
  /// <param name="serverUrl">ACME server URL (e.g., acme-v02.api.letsencrypt.org)</param>
  /// <returns>Account object met ID en URL</returns>
  Task<Account> GetOrCreateAccountAsync(string keyJwk, string serverUrl);

  /// <summary>
  /// Haal een challenge op door zijn ID.
  /// </summary>
  /// <param name="challengeId">Challenge identifier van de authorization</param>
  /// <returns>Challenge object</returns>
  Task<Challenge> GetChallengeAsync(string challengeId);

  /// <summary>
  /// Update de status van een challenge (pending, valid, invalid).
  /// </summary>
  /// <param name="challengeId">Challenge identifier</param>
  /// <param name="status">Nieuwe status conform RFC 8555</param>
  Task SetChallengeStatusAsync(string challengeId, ChallengeStatus status);

  /// <summary>
  /// Haal de huidige DNS TXT record op voor een validatie domein.
  /// </summary>
  /// <param name="validationDomain">Validatie domein (e.g., _acme-challenge.example.com)</param>
  /// <returns>TXT record waarde</returns>
  Task<string?> GetDnsRecordAsync(string validationDomain);

  /// <summary>
  /// Provisioneer een DNS TXT record voor validation.
  /// </summary>
  /// <param name="validationDomain">Validatie domein</param>
  /// <param name="value">TXT record waarde (base64 van key authorization digest)</param>
  Task SetDnsRecordAsync(string validationDomain, string value);

  /// <summary>
  /// Haal de private key op voor een account door zijn key ID.
  /// </summary>
  /// <param name="accountKeyId">Account key identifier</param>
  /// <returns>Private key in bytes (unencrypted)</returns>
  Task<byte[]> GetPrivateKeyAsync(string accountKeyId);

  /// <summary>
  /// Sla een certificate bundle op voor een domein.
  /// </summary>
  /// <param name="domainName">Domein waarvoor het cert geldig is</param>
  /// <param name="certificate">Leaf certificate in PEM bytes</param>
  /// <param name="privateKey">Private key in PEM bytes</param>
  Task SaveCertificateAsync(string domainName, byte[] certificate, byte[] privateKey);

  /// <summary>
  /// Haal een opgeslagen certificate bundle op.
  /// </summary>
  /// <param name="domainName">Domein van het certificate</param>
  /// <returns>CertificateBundle object</returns>
  Task<CertificateBundle?> GetCertificateAsync(string domainName);

  /// <summary>
  /// Verwijder een opgeslagen certificate bundle.
  /// </summary>
  /// <param name="domainName">Domein van het certificate</param>
  Task RemoveCertificateAsync(string domainName);

  /// <summary>
  /// Haal alle opgeslagen certificaten op.
  /// </summary>
  /// <returns>Lijst van CertificateBundle objects</returns>
  Task<List<CertificateBundle>> GetAllCertificatesAsync();
}
