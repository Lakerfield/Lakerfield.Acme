# Lakerfield.Acme - Implementation Plan

## Goal

A simple .NET 10 library that implements the ACME protocol (RFC 8555) for communication with Let's Encrypt. The library is a **thin wrapper** around `HttpClient` and provides no YARP integration — the host application (e.g. a YARP-based reverse proxy) drives all logic.

## Architecture

```
LakerfieldAcmeClient
├── Account management
├── Challenge management
│   ├── HTTP-01 challenge
│   ├── DNS-01 challenge
│   └── TLS-ALPN-01 challenge
└── Certificate bundling & renewal
```

**This is a pure ACME client library** — no YARP-specific integration, no DI containers, pure HTTP calls to ACME servers.

## User Requirements Overview

| Requirement | Implementation |
|-------------|----------------|
| **Challenges** | HTTP-01, DNS-01, TLS-ALPN-01 (RFC 8737) |
| **Wildcards** | True DNS wildcards for subdomains via DNS-01 |
| **Storage** | Interface for storage (MongoDB or disk) — host app implements |
| **Certificates** | In-memory lifecycle via storage interface |
| **ACME Server** | Let's Encrypt (`acme-v02.api.letsencrypt.org`) |

## Interfaces and Contracts

### 1. Storage Interface

The library defines a **storage interface** that the host application implements:

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

The host application (YARP proxy) implements this interface with MongoDB or disk storage.

### 2. LakerfieldAcmeClient Constructor

The client receives the storage interface via the constructor — no DI dependencies:

```csharp
var client = new LakerfieldAcmeClient(
    httpClient,       // Optional, uses a default HttpClient if omitted
    storage,          // External implementation
    retryPolicy       // Optional AcmeRetryConfig
);
client.AcmeServerUrl = "https://acme-v02.api.letsencrypt.org/directory";
```

## Challenges & Wildcards

**HTTP-01 & TLS-ALPN-01**: RFC 8555 specifies that these challenges do **not** support true wildcards. Each hostname requires its own challenge:

```
www.example.com  → individual challenge
api.example.com  → individual challenge
mail.example.com → individual challenge
```

**DNS-01**: Supports true DNS wildcards such as `*.example.com` by setting a TXT record on `_acme-challenge.example.com`.

### Challenge Workflow

1. `client.LoadDirectoryAsync()` — Load ACME directory
2. `client.GenerateAccountKey()` — Generate EC P-256 key
3. `client.CreateAccountAsync(email)` — Create account
4. `client.CreateOrderAsync(domain)` — Place certificate order
5. `client.GetAuthorizationAsync(authzUrl)` — Retrieve authorization
6. Provision the challenge (HTTP file, DNS TXT record, or TLS cert)
7. `client.ValidateChallengeAsync(challengeUrl)` — Notify ACME server
8. `client.WaitForChallengeValidAsync(challengeUrl)` — Poll until valid
9. `client.WaitForOrderReadyAsync(orderUrl)` — Wait for order ready
10. `client.FinalizeOrderAsync(order, domains)` — Submit CSR
11. `client.WaitForOrderValidAsync(orderUrl)` — Wait for order valid
12. `client.DownloadCertificateAsync(order)` — Download PEM certificate

## Implementation Plan

### Phase 1: Core Infrastructure ✅

1. **Project structure**
   - `Lakerfield.Acme` project targeting .NET 10
   - No external NuGet dependencies (uses `System.Net.Http`, `System.Text.Json`, `System.Security.Cryptography`)

2. **Model classes**
   - `Account` (RFC 8555 §7.1.2)
   - `Challenge` (RFC 8555 §7.1.5)
   - `Authorization` (RFC 8555 §7.1.4)
   - `AcmeOrder` (RFC 8555 §7.1.3)
   - `AcmeDirectory` (RFC 8555 §7.1.1)
   - `CertificateBundle`

3. **Storage interface**
   - `IAcmeStorage` with all required methods
   - User implements MongoDB/disk storage

### Phase 2: Account Management ✅

4. **Account endpoint calls**
   - `POST /acme/new-account` — create account
   - `POST-as-GET` on account URL — load existing account
   - JWS signing with EC P-256 (ES256)
   - Account key generation and loading

### Phase 3: Authorization & Challenges ✅

5. **Authorization endpoint**
   - `POST-as-GET /acme/authz-v3/{id}` — fetch authorization
   - Challenge object parsing

6. **Challenge types**
   - HTTP-01: `GetHttpChallengeValue(token)`
   - DNS-01: `GetDnsChallengeValue(token)`, `GetDnsValidationDomain(domain)`
   - TLS-ALPN-01: `GenerateTlsAlpnCertificate(domain, token)` (RFC 8737)

### Phase 4: Certificate Issuance ✅

7. **Order finalization**
   - `POST /acme/new-order` — create order
   - CSR generation with SAN extensions
   - `POST /acme/order/{id}/finalize` — submit CSR
   - PEM certificate download
   - Certificate revocation (RFC 8555 §7.6)
   - Account deactivation (RFC 8555 §7.3.6)

### Phase 5: Testing & Documentation ✅

8. **Playground application**
   - Minimal ASP.NET Core web app for HTTP-01 challenge hosting
   - `AcmeChallengeTokenStore` + `AcmeChallengeExtensions`
   - Full end-to-end workflow demonstration
   - `InMemoryAcmeStorage` for demo/testing

9. **Documentation**
   - `README.md` with usage examples
   - XML documentation on all public APIs
   - English comments throughout

## Technical Specifications

### JSON Serialization

Let's Encrypt uses a custom format with `protected`, `payload`, `signature` fields (RFC 7515 flattened JSON serialization):

```csharp
return JsonSerializer.Serialize(new
{
    @protected = protectedB64,
    payload    = payloadB64,
    signature  = signatureB64,
});
```

### JWS Implementation

**Custom JWS implementation** in `JwtHelper`:
- ECDSA P-256 (ES256) signing via `System.Security.Cryptography`
- Base64Url encoding as per RFC 7515
- JWK thumbprint computation as per RFC 7638
- No external dependencies

### Directory Endpoint Discovery

Let's Encrypt directory:
```
https://acme-v02.api.letsencrypt.org/directory   (production)
https://acme-staging-v02.api.letsencrypt.org/directory  (staging)
```

### TLS-ALPN-01 Certificate

For TLS-ALPN-01, the library uses standard .NET capabilities:
- `System.Security.Cryptography.X509Certificates` for certificate generation
- `acmeIdentifier` extension via custom OID `1.3.6.1.5.5.7.1.31` (RFC 8737 §3)
- Self-signed certificate with SHA-256 digest of key authorization

### Error Handling & Retry

Built-in retry policy via `AcmeRetryConfig`:
- Exponential backoff (configurable, default 3 attempts)
- Configurable timeout per request
- Automatic retry on HTTP 5xx errors

### Nonce Management

- Nonces are cached from previous responses (`Replay-Nonce` header)
- `GetNonceAsync()` fetches a fresh nonce via HEAD on `newNonce` endpoint
- `ConsumeNonceAsync()` reuses the cached nonce or fetches a new one

---

*Standalone ACME library without YARP dependencies — the host application drives all logic.*

