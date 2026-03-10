# Lakerfield.Acme - Implementatieplan

## Doel

Een simpele .NET 10 library die de ACME protocol (RFC 8555) implementeert voor communicatie met Let's Encrypt. De library is een **losse wrapper** rondom `HttpClient` en biedt geen YARP-integratie - de externe app (YARP-based reverse proxy) stuurt alle logica aan.

## Architectuur

```
LakerfieldAcmeClient
├── Account management
├── Challenge management
│   ├── HTTP-01 challenge
│   ├── DNS-01 challenge
│   └── TLS-ALPN-01 challenge
└── Certificate bundling & renewal
```

**Dit is een pure ACME client library** - geen YARP specifieke integratie, geen DI containers, puur HTTP calls naar ACME servers.

## Overzicht van Gebruikerseisen

| Vereiste | Implementatie |
|----------|---------------|
| **Challenges** | HTTP-01, DNS-01, TLS-ALPN-01 (RFC 8737) |
| **Wildcards** | Echte DNS wildcards voor subdomains via DNS-01 |
| **Storage** | Interface voor storage (MongoDB of disk) - externe app implementeert |
| **Certificates** | In-memory lifecycle via storage interface |
| **ACME Server** | Let's Encrypt (`acme-v02.api.letsencrypt.org`) |

## Interfaces en Contracten

### 1. Storage Interface

De library definieert een **interface voor storage** die de externe app implementeert:

```csharp
public interface IAcmeStorage : IDisposable
{
    Task<Account> GetOrCreateAccountAsync(string keyJwk, string serverUrl);
    Task<Challenge> GetChallengeAsync(string challengeId);
    Task SetChallengeStatusAsync(string challengeId, ChallengeStatus status);
    Task<string> GetDnsRecordAsync(string validationDomain);
    Task SetDnsRecordAsync(string validationDomain, string value);
    Task<byte[]> GetPrivateKeyAsync(AccountKeyIdentifier keyRef);
    Task SaveCertificateAsync(string domainName, byte[] certificate, byte[] privateKey);
}
```

De externe app (YARP proxy) implementeert deze interface met MongoDB of disk storage.

### 2. LakerfieldAcmeClient Constructor

De client ontvangt de storage interface via constructor - geen DI dependencies:

```csharp
var client = new LakerfieldAcmeClient(
    httpClient,           // Optioneel, standaard HttpClient gebruiken ook
    storage,              // Externe implementatie
    acmeServerUrl         // "https://acme-v02.api.letsencrypt.org/directory"
);
```

## Challenges & Wildcards

**HTTP-01 & TLS-ALPN-01**: RFC 8555 specificeert dat deze challenges géén echte wildcards ondersteunen. Implementatie:

```
www.example.com → aparte challenge
api.example.com → aparte challenge
mail.example.com → aparte challenge
```

**DNS-01**: Ondersteunt echte DNS wildcards zoals `_docusign.example.com` door de storage interface aan te laten zien dat een TXT record voor een wildcard wordt aangevraagd.

### Challenges Workflow

1. `client.CreateAccount()` - Account aanmaken
2. `client.RequestAuthorization(domain)` - Authorization request
3. `client.Challenges[challengeId].Status = "pending"` (via storage interface)
4. `await client.ValidateChallenge(challengeId)` - Validation via HTTP/DNS/ALPN
5. `client.GetCertificate(accountId, domain)` - Certificate ophalen

## Implementatie Plan

### Fase 1: Core Infrastructure (Dag 1-2)

1. **Project structuur setup**
   - `Lakerfield.Acme` project met .NET 10 target framework
   - NuGet dependencies: `System.Net.Http`, `System.Text.Json`

2. **Model classes**
   - `Account` (RFC 8555 §6)
   - `Challenge` (RFC 8555 §3, §6)
   - `Authorization` (RFC 8555 §4)
   - `CertificateBundle` (RFC 8555 §7.5)

3. **Storage interface**
   - `IAcmeStorage` met alle benodigde methods
   - Gebruiker implementeert MongoDB/disk storage zelf

### Fase 2: Account Management (Dag 2-3)

4. **Account endpoint calls**
   - `POST /acme/new-account`
   - JWS signing van account requests
   - Account key management

### Fase 3: Authorization & Challenges (Dag 3-4)

5. **Authorization endpoint**
   - `POST /acme/new-authz`
   - Challenge object parsing
   - Challenge status tracking

6. **Challenge types**
   - HTTP-01 manager
   - DNS-01 manager
   - TLS-ALPN-01 manager (RFC 8737)

### Fase 4: Certificate Issuance (Dag 4-5)

7. **Certificate endpoint**
   - `POST /acme/new-cert`
   - Certificate bundle parsing (CER + PFX/CRT+KEY)
   - Nonce management voor ACME v2

### Fase 5: Testing (Dag 5-6)

8. **Playground usage**
   - Test scenarios voor elke challenge type
   - Mock storage implementation in playground project

9. **Documentation**
   - API documentation
   - Usage examples
   - Troubleshooting guide

## Technische Specificaties

### JSON Serialization

Let's Encrypt gebruikt een custom formatter met `protected`, `payload`, `signature` fields:

```csharp
[JsonPropertyName("protected")]
public string JwsProtected { get; set; }

[JsonPropertyName("payload")]
public string Payload => JsonConvert.SerializeObject(JwePayload);

[JsonPropertyName("signature")]
public string Signature { get; set; }
```

### JWS/JWE Implementatie

**Custom JWS implementatie**: Compacte class met ECDSA/RS256 signing via `System.Security.Cryptography`. Base64Url encoding conform RFC 7515.

### Directory Endpoint Discovery

Let's Encrypt directory:
```
https://acme-v02.api.letsencrypt.org/directory
```

Ondersteund metadata:
- `newAccount` / `newAuthz` endpoints voor ACME v2
- `newNonce` endpoint voor nonce management
- `revokeCert` / `deactivate*` endpoints voor cleanup

### TLS ALPN Certificate

Voor TLS-ALPN-01 zal we **standaard .NET capabilities** gebruiken:
- `System.Security.Cryptography.X509Certificates` voor certificate generatie
- `acmeIdentifier` extensie via custom OID (31)
- Self-signed cert met SHA-256 digest van key authorization

## Technisch Gedetailleerd

### 1. JWS Implementatie (Custom)

Een zelfgeschreven class die:
- ECDSA/RSA signing met `System.Security.Cryptography`
- Base64Url encoding conform RFC 7515
- Compacte implementation, geen externe dependencies

### 2. Error Handling & Retry

De library bouwt **ingebouwde retry policies** in:
- Exponential backoff (3 pogingen standaard)
- Timeout configuratie per endpoint
- Retry alleen op HTTP 429 (rate limit), 5xx errors

### 3. Multi-threading & Concurrent Access

De client maakt **read-only access** mogelijk op accounts/certificaten:
- Accounts/keys zijn readonly voor concurrente reads
- Writes (status updates) gebeuren via storage interface, niet binnen client
- Externe app beheret concurrente write toegang

### 4. Logging

Serilog integration via `ILogger` interface:
- `ILogger<LakerfieldAcmeClient>` injectie
- Opties voor Console logging als fallback

## Directory Endpoint Discovery

## Volgende Stappen

1. Geef antwoord bovenstaande open vragen
2. Review het plan.md document
3. Goedkeuring van architectuur beslissingen
4. Start implementatie met Fase 1

---

*Losse ACME library zonder YARP dependencies - externe app stuurt logica aan*
