# Lakerfield.Acme

A simple .NET 10 library for interacting with ACME (Automated Certificate Management Environment) servers, implementing [RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555). Compatible with Let's Encrypt and any other RFC 8555 compliant CA.

## Features

- **Account management** — create and load ACME accounts with EC P-256 keys
- **HTTP-01, DNS-01, and TLS-ALPN-01 challenges** (DNS-01 supports wildcard certificates)
- **Certificate ordering, finalization, and download** — full end-to-end workflow
- **Certificate revocation** and account deactivation
- **No external dependencies** — uses only built-in .NET APIs (`System.Net.Http`, `System.Text.Json`, `System.Security.Cryptography`)
- **Storage agnostic** — implement `IAcmeStorage` to use MongoDB, disk, or any other backend
- **Configurable retry policy** with exponential backoff

## Installation

```bash
dotnet add package Lakerfield.Acme
```

## Quick Start

```csharp
using Lakerfield.Acme;
using Lakerfield.Acme.Models;

// 1. Create the client (provide your IAcmeStorage implementation)
var storage = new MyAcmeStorage(); // your implementation of IAcmeStorage
using var client = new LakerfieldAcmeClient(new HttpClient(), storage);

// Use Let's Encrypt staging for testing
client.AcmeServerUrl = "https://acme-staging-v02.api.letsencrypt.org/directory";

// 2. Load the ACME directory
await client.LoadDirectoryAsync();

// 3. Generate an account key and create an account
var privateKeyBytes = client.GenerateAccountKey();
var account = await client.CreateAccountAsync(email: "admin@example.com");

// Save privateKeyBytes and account.Url for future use!

// 4. Create an order for a domain
var domain = "example.com";
var order = await client.CreateOrderAsync(domain);

// 5. Process each authorization
foreach (var authzUrl in order.Authorizations)
{
    var authz = await client.GetAuthorizationAsync(authzUrl);

    // Find the HTTP-01 challenge
    var httpChallenge = authz.Challenges.FirstOrDefault(c => c.Type == "http-01");
    if (httpChallenge != null)
    {
        var token = httpChallenge.Token!;
        var keyAuth = client.GetHttpChallengeValue(token);

        // Serve keyAuth at: http://<domain>/.well-known/acme-challenge/<token>
        // ... set up your HTTP server to respond to this path ...

        // Notify the ACME server that the challenge is ready
        await client.ValidateChallengeAsync(httpChallenge.Url!);

        // Wait for validation to complete
        var validated = await client.WaitForChallengeValidAsync(httpChallenge.Url!);
    }
}

// 6. Wait for the order to be ready and finalize it
var readyOrder = await client.WaitForOrderReadyAsync(order.Url!);
var (pendingOrder, certPrivateKey) = await client.FinalizeOrderAsync(readyOrder, new[] { domain });

// 7. Wait for the certificate and download it
var validOrder = await client.WaitForOrderValidAsync(pendingOrder.Url!);
var pemCertificate = await client.DownloadCertificateAsync(validOrder);
// certPrivateKey contains the PKCS#8 DER-encoded private key for the certificate
```

## Challenge Types

### HTTP-01

Serve the key authorization value at `http://<domain>/.well-known/acme-challenge/<token>`:

```csharp
var keyAuth = client.GetHttpChallengeValue(token);
// Serve keyAuth at the well-known URL, then call:
await client.ValidateChallengeAsync(httpChallenge.Url!);
```

### DNS-01

Set a DNS TXT record on `_acme-challenge.<domain>` (supports wildcard domains):

```csharp
var dnsTxtValue = client.GetDnsChallengeValue(token);
var dnsValidationDomain = LakerfieldAcmeClient.GetDnsValidationDomain(domain);
// Set TXT record: dnsValidationDomain => dnsTxtValue
await client.ValidateChallengeAsync(dnsChallenge.Url!);
```

### TLS-ALPN-01

Generate a self-signed certificate with the `acmeIdentifier` OID extension (RFC 8737):

```csharp
var cert = client.GenerateTlsAlpnCertificate(domain, token);
// Serve cert during TLS handshake with ALPN "acme-tls/1", then call:
await client.ValidateChallengeAsync(tlsChallenge.Url!);
```

## Loading an Existing Account

```csharp
// Load the saved private key and account URL from storage
var savedKey = await File.ReadAllBytesAsync("acme-account-key.der");
var savedAccountUrl = await File.ReadAllTextAsync("acme-account-url.txt");

await client.LoadDirectoryAsync();
var account = await client.LoadAccountAsync(savedAccountUrl, savedKey);
```

## Storage Interface

Implement `IAcmeStorage` to persist ACME data using any backend:

```csharp
public interface IAcmeStorage : IDisposable
{
    Task<Account> GetOrCreateAccountAsync(string keyJwk, string serverUrl);
    Task<Challenge> GetChallengeAsync(string challengeId);
    Task SetChallengeStatusAsync(string challengeId, ChallengeStatus status);
    Task<string?> GetDnsRecordAsync(string validationDomain);
    Task SetDnsRecordAsync(string validationDomain, string value);
    Task<byte[]> GetPrivateKeyAsync(string accountKeyId);
    Task SaveCertificateAsync(string domainName, byte[] certificate, byte[] privateKey);
    Task<CertificateBundle?> GetCertificateAsync(string domainName);
    Task RemoveCertificateAsync(string domainName);
    Task<List<CertificateBundle>> GetAllCertificatesAsync();
}
```

## Retry Policy

Customize the retry behavior:

```csharp
var retryConfig = new AcmeRetryConfig
{
    MaxAttempts = 5,
    InitialDelaySeconds = 2,
    MaxDelaySeconds = 60,
    ExponentialBase = 2,
};
using var client = new LakerfieldAcmeClient(new HttpClient(), storage, retryConfig);
```

## Playground

The `src/Lakerfield.Acme.Playground` project demonstrates the complete workflow end-to-end:

- Creates a minimal ASP.NET Core web app to handle HTTP-01 challenge responses
- Loads or creates an ACME account (persists key to temp directory)
- Creates an order, processes HTTP-01 and DNS-01 challenges
- Finalizes the order and downloads the PEM certificate chain

Run the playground (requires port 80 access for HTTP-01 validation):

```bash
dotnet run --project src/Lakerfield.Acme.Playground
```

Sample output:
```
Lakerfield.Acme Playground
==========================

ACME Server: https://acme-staging-v02.api.letsencrypt.org/directory

Step 1: Loading ACME directory...
  newAccount: https://acme-staging-v02.api.letsencrypt.org/acme/new-acct
  newOrder:   https://acme-staging-v02.api.letsencrypt.org/acme/new-order
  newNonce:   https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce

Step 2: Creating new account...
  EC P-256 private key generated (138 bytes)
  Account created: https://acme-staging-v02.api.letsencrypt.org/acme/acct/123456789
  Account status: valid
  Private key saved: /tmp/acme-account-key.der
  Account URL saved: /tmp/acme-account-url.txt

Step 3: Creating order for example.com...
  Order URL: https://acme-staging-v02.api.letsencrypt.org/acme/order/...
  Order status: pending
  Authorizations: 1

Step 4: Processing authorizations...
  Authorization: https://acme-staging-v02.api.letsencrypt.org/acme/authz-v3/...
  Domain: example.com
  Status: pending
    Challenge type: http-01, status: pending
    Challenge type: dns-01, status: pending
    Challenge type: tls-alpn-01, status: pending

  HTTP-01 Challenge:
    Token: <token>
    Key Authorization: <token>.<thumbprint>
    URL: http://example.com/.well-known/acme-challenge/<token>

  Token registered on the local web app:
    http://example.com/.well-known/acme-challenge/<token>

  Validating challenge...
  Waiting for challenge validation...
  Challenge status: valid

  DNS-01 (as alternative):
    TXT record domain: _acme-challenge.example.com
    TXT record value:  <base64url-digest>

Step 5: Requesting and downloading certificate...
  Waiting for order to become 'ready'...
  Order status: ready
  Finalizing order (submitting CSR)...
  Order status after finalize: processing
  Waiting for order to become 'valid'...
  Order status: valid
  Downloading certificate...

─── PEM Certificate ────────────────────────────────────────────────────────
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
────────────────────────────────────────────────────────────────────────────

Demo completed successfully!
```

## ACME Server URLs

| Environment | URL |
|-------------|-----|
| Let's Encrypt Production | `https://acme-v02.api.letsencrypt.org/directory` |
| Let's Encrypt Staging | `https://acme-staging-v02.api.letsencrypt.org/directory` |

## Building

```bash
dotnet build
```

## License

See [LICENSE](LICENSE) for details.
