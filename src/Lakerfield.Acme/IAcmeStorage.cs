using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Lakerfield.Acme.Models;

namespace Lakerfield.Acme;

/// <summary>
/// Storage interface for ACME credentials and validation data.
/// Implementations can use MongoDB, disk, or any other storage backend.
/// </summary>
public interface IAcmeStorage : IDisposable
{
  /// <summary>
  /// Retrieves or creates an account for the given private key.
  /// </summary>
  /// <param name="keyJwk">Base64Url-encoded private key JWK</param>
  /// <param name="serverUrl">ACME server URL (e.g., acme-v02.api.letsencrypt.org)</param>
  /// <returns>Account object with ID and URL</returns>
  Task<Account> GetOrCreateAccountAsync(string keyJwk, string serverUrl);

  /// <summary>
  /// Retrieves a challenge by its ID.
  /// </summary>
  /// <param name="challengeId">Challenge identifier from the authorization</param>
  /// <returns>Challenge object</returns>
  Task<Challenge> GetChallengeAsync(string challengeId);

  /// <summary>
  /// Updates the status of a challenge (pending, valid, invalid).
  /// </summary>
  /// <param name="challengeId">Challenge identifier</param>
  /// <param name="status">New status as per RFC 8555</param>
  Task SetChallengeStatusAsync(string challengeId, ChallengeStatus status);

  /// <summary>
  /// Retrieves the current DNS TXT record for a validation domain.
  /// </summary>
  /// <param name="validationDomain">Validation domain (e.g., _acme-challenge.example.com)</param>
  /// <returns>TXT record value</returns>
  Task<string?> GetDnsRecordAsync(string validationDomain);

  /// <summary>
  /// Provisions a DNS TXT record for validation.
  /// </summary>
  /// <param name="validationDomain">Validation domain</param>
  /// <param name="value">TXT record value (base64 of key authorization digest)</param>
  Task SetDnsRecordAsync(string validationDomain, string value);

  /// <summary>
  /// Retrieves the private key for an account by its key ID.
  /// </summary>
  /// <param name="accountKeyId">Account key identifier</param>
  /// <returns>Private key bytes (unencrypted)</returns>
  Task<byte[]> GetPrivateKeyAsync(string accountKeyId);

  /// <summary>
  /// Saves a certificate bundle for a domain.
  /// </summary>
  /// <param name="domainName">Domain for which the certificate is valid</param>
  /// <param name="certificate">Leaf certificate in PEM bytes</param>
  /// <param name="privateKey">Private key in PEM bytes</param>
  Task SaveCertificateAsync(string domainName, byte[] certificate, byte[] privateKey);

  /// <summary>
  /// Retrieves a stored certificate bundle.
  /// </summary>
  /// <param name="domainName">Domain of the certificate</param>
  /// <returns>CertificateBundle object</returns>
  Task<CertificateBundle?> GetCertificateAsync(string domainName);

  /// <summary>
  /// Removes a stored certificate bundle.
  /// </summary>
  /// <param name="domainName">Domain of the certificate</param>
  Task RemoveCertificateAsync(string domainName);

  /// <summary>
  /// Retrieves all stored certificates.
  /// </summary>
  /// <returns>List of CertificateBundle objects</returns>
  Task<List<CertificateBundle>> GetAllCertificatesAsync();
}
