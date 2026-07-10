![Lakerfield.Acme logo](https://raw.githubusercontent.com/Lakerfield/Lakerfield.Acme/main/assets/lakerfield-acme-icon-256.png)

# Lakerfield.Acme

A simple .NET 10 library for interacting with ACME (Automated Certificate Management Environment) servers, implementing [RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555). Compatible with Let's Encrypt and any other RFC 8555 compliant CA.

## Features

- **Account management** — create and load ACME accounts with EC P-256 keys
- **HTTP-01 and DNS-01 challenges** (DNS-01 supports wildcard certificates)
- **TLS-ALPN-01 certificate generation helper** — generates the self-signed challenge certificate (RFC 8737), but serving it during the TLS/ALPN handshake is not implemented
- **Certificate ordering, finalization, and download** — full end-to-end workflow
- **Certificate revocation** and account deactivation
- **No external dependencies for the core client** — uses only built-in .NET APIs (`System.Net.Http`, `System.Text.Json`, `System.Security.Cryptography`)
- **Storage agnostic** — the client itself is stateless between calls; persist the account key, account URL, and certificates however you like
- **Configurable retry policy** with exponential backoff
- **Optional forwarded DNS-01 server** — `AddAcmeDnsServer()` hosts a minimal authoritative DNS server for CNAME-forwarded `_acme-challenge` validation

## Installation

```bash
dotnet add package Lakerfield.Acme
```

## Quick Start

```csharp
using Lakerfield.Acme;
using Lakerfield.Acme.Models;

// 1. Create the client — use WellKnownServers.LetsEncryptStaging for testing
using var client = new LakerfieldAcmeClient(WellKnownServers.LetsEncryptStaging, new HttpClient());

// 2. Load the ACME directory
await client.LoadDirectoryAsync();

// 3. Generate an account key and create an account
var privateKeyBytes = client.GenerateAccountKey();
var account = await client.CreateAccountAsync(email: "admin@example.com", termsOfServiceAgreed: false); // set to true if you accept the tos of the provider

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

### TLS-ALPN-01 (experimental — not implemented end-to-end)

`GenerateTlsAlpnCertificate` generates a self-signed certificate with the `acmeIdentifier` OID extension (RFC 8737), but the library does not include a TLS listener that presents this certificate during the `acme-tls/1` ALPN handshake. You would need to build that part yourself, and this challenge type has not been tested against a real ACME server:

```csharp
var cert = client.GenerateTlsAlpnCertificate(domain, token);
// You must serve this cert yourself during the TLS handshake with ALPN protocol "acme-tls/1" — not provided by this library.
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

## Persisting State

`LakerfieldAcmeClient` has no built-in storage — it's up to the host application to persist whatever it needs between calls:

- The account private key (from `GenerateAccountKey()`) and `account.Url`, so you can call `LoadAccountAsync` later instead of creating a new account.
- The certificate private key and PEM chain returned by `FinalizeOrderAsync`/`DownloadCertificateAsync`, using whatever storage backend fits (disk, database, secret manager, ...).

See [Loading an Existing Account](#loading-an-existing-account) above for the account key/URL round-trip.

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
using var client = new LakerfieldAcmeClient(WellKnownServers.LetsEncryptStaging, new HttpClient(), retryConfig);
```

## Forwarded DNS-01 Server

For DNS-01 validation without giving the library write access to your real DNS zone, `AddAcmeDnsServer` hosts a minimal authoritative DNS server that answers TXT queries for a dedicated zone. Point a `CNAME` from `_acme-challenge.<domain>` to that zone and the ACME server will follow the forward to resolve the TXT record:

```csharp
using Microsoft.Extensions.DependencyInjection;

builder.Services.AddAcmeDnsServer(options =>
{
    options.BindAddress = IPAddress.Any;
    options.Port = 53;
    options.ZoneName = "acme.example.com";
    options.DefaultTtl = 30;
});

// Later, once you have the DNS-01 value for a challenge:
var dnsStore = app.Services.GetRequiredService<IAcmeDnsChallengeStore>();
var forwardLabel = LakerfieldAcmeClient.GetDnsValidationForwardLabel(domain);
dnsStore.SetTxtRecord($"{forwardLabel}.acme.example.com", dnsValue, ttl: 30, validFor: TimeSpan.FromMinutes(10));
```

## Playground

The `src/Lakerfield.Acme.Playground` project demonstrates the complete workflow end-to-end:

- Creates a minimal ASP.NET Core web app to handle HTTP-01 challenge responses and hosts the forwarded DNS-01 server
- Loads or creates an ACME account (persists key to temp directory)
- Creates an order, processes HTTP-01 and DNS-01 challenges
- Finalizes the order and downloads the PEM certificate chain

Run the playground (requires port 80 access for HTTP-01 validation, and port 53 for the forwarded DNS-01 server):

```bash
dotnet run --project src/Lakerfield.Acme.Playground
```

Sample output of a wildcard certificate request:
```
Lakerfield.Acme Playground
==========================

ACME Server: https://acme-staging-v02.api.letsencrypt.org/directory

Step 1: Loading ACME directory...
  newAccount: https://acme-staging-v02.api.letsencrypt.org/acme/new-acct
  newOrder:   https://acme-staging-v02.api.letsencrypt.org/acme/new-order
  newNonce:   https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce
  profiles:
    classic: https://letsencrypt.org/docs/profiles#classic
    shortlived: https://letsencrypt.org/docs/profiles#shortlived
    tlsserver: https://letsencrypt.org/docs/profiles#tlsserver

Step 2: Creating new account...
  EC P-256 private key generated (138 bytes)
  Account created: https://acme-staging-v02.api.letsencrypt.org/acme/acct/1234
  Account status: valid
  Private key saved: /tmp/acme-account-key.der
  Account URL saved: /tmp/acme-account-url.txt

Step 3: Creating order for example.com, *.example.com...
  Order URL: https://acme-staging-v02.api.letsencrypt.org/acme/order/1234/12345
  Order status: pending
  Authorizations: 2

Step 4: Processing authorizations...
  Authorization: https://acme-staging-v02.api.letsencrypt.org/acme/authz-v3/1234/123456
  Domain: example.com
  Status: pending
    Challenge type: dns-persist-01, status: pending
    Challenge type: dns-01, status: pending
  DNS-01 (as alternative):
    TXT record:         _acme-challenge.example.com
    TXT record value:   <token>
    or CNAME forwarded: example-com.acme.example-provider.com
  Validating challenge...
  Waiting for challenge validation...
eXAmpLe-cOM.acMe.ExampLe-ProVider.COM => <token>
eXAMpLE-com.acmE.eXaMPle-prOviDER.Com => <token>
EXAMple-coM.AcMe.EXampLE-PROvideR.com => <token>
examPLe-Com.aCme.ExAMPLE-PROViDeR.coM => <token>
  Challenge status: valid
  Authorization: https://acme-staging-v02.api.letsencrypt.org/acme/authz/1234/123457
  Domain: example.com
  Status: pending
    Challenge type: dns-01, status: pending
    Challenge type: dns-persist-01, status: pending
    Challenge type: http-01, status: pending
    Challenge type: tls-alpn-01, status: pending


  HTTP-01 Challenge:
    Token: <token>
    Key Authorization: <token>.<thumbprint>
    URL: http://example.com/.well-known/acme-challenge/<token>

  Token registered on the local web app:
    http://example.com/.well-known/acme-challenge/<token>

  Validating challenge...
  Waiting for challenge validation...
http://example.com/.well-known/acme-challenge/<token> - 200
http://example.com/.well-known/acme-challenge/<token> - 200
http://example.com/.well-known/acme-challenge/<token> - 200
http://example.com/.well-known/acme-challenge/<token> - 200
  Challenge status: valid

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
... encoded certificate
- Common Name: example.com
- Subject Alternative Names: *.example.com, example.com
- Valid From: ...
- Valid To: ...
- Serial Number: ...
...
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
... encoded intermediate certificate
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
... encoded root certificate
-----END CERTIFICATE-----

────────────────────────────────────────────────────────────────────────────

Demo completed successfully!
```

## ACME Server URLs

`WellKnownServers` provides `Uri`s for common CAs so you don't have to hardcode them:

| Environment | `WellKnownServers` member | URL |
|-------------|----------------------------|-----|
| Let's Encrypt Production | `LetsEncrypt` | `https://acme-v02.api.letsencrypt.org/directory` |
| Let's Encrypt Staging | `LetsEncryptStaging` | `https://acme-staging-v02.api.letsencrypt.org/directory` |
| ZeroSSL | `ZeroSsl` | `https://acme.zerossl.com/v2/DV90` |

Any other RFC 8555 compliant CA works too — just pass its directory `Uri` to the `LakerfieldAcmeClient` constructor.

## Building

```bash
dotnet build
```

## License

See [LICENSE](LICENSE) for details.
