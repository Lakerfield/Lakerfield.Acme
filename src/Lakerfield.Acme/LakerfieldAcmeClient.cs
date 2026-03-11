using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using Lakerfield.Acme.Models;

namespace Lakerfield.Acme;

/// <summary>
/// ACME client voor communicatie met Let's Encrypt (en andere RFC 8555 compatible servers).
/// Losse library zonder DI dependencies - externe app stuurt logica.
/// </summary>
public class LakerfieldAcmeClient : IDisposable
{
  private readonly HttpClient _httpClient;
  private readonly IAcmeStorage _storage;
  private readonly RetryHelper.AcmeRetryConfig _retryPolicy;
  private Account? _account;

  /// <summary>
  /// ACME directory URL (standard: Let's Encrypt)
  /// </summary>
  public string AcmeServerUrl { get; set; } = "https://acme-v02.api.letsencrypt.org/directory";

  /// <summary>
  /// Loaded ACME account na aanmaken.
  /// </summary>
  public Account? Account => _account;

  /// <summary>
  /// Current authorization met Challenges.
  /// </summary>
  public Authorization? Authorization { get; private set; }

  /// <summary>
  /// List van active challenges.
  /// </summary>
  public Dictionary<string, Challenge> Challenges { get; } = new();

  public LakerfieldAcmeClient(HttpClient httpClient, IAcmeStorage storage,
    RetryHelper.AcmeRetryConfig? retryPolicy = null)
  {
    _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
    _storage = storage ?? throw new ArgumentNullException(nameof(storage));
    _retryPolicy = retryPolicy ?? RetryHelper.DefaultRetryPolicy;

    // Configure user agent
    _httpClient.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("Lakerfield.Acme", "1.0"));
    _httpClient.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue($"DotNet/{Environment.Version}"));

    // Haal directory URL op
    LoadDirectoryAsync().GetAwaiter().GetResult();
  }

  /// <summary>
  /// Factory methode zonder explicit HttpClient - gebruikt default.
  /// </summary>
  public LakerfieldAcmeClient(IAcmeStorage storage, RetryHelper.AcmeRetryConfig? retryPolicy = null) : this(
    new HttpClient(), storage, retryPolicy)
  {
  }

  /// <summary>
  /// Load ACME directory endpoint.
  /// </summary>
  public async Task LoadDirectoryAsync()
  {
    try
    {
      var response = await _httpClient.GetAsync(string.Empty).ConfigureAwait(false);

      if (!response.IsSuccessStatusCode)
      {
        throw new HttpRequestException($"Failed to connect to ACME server at {AcmeServerUrl}");
      }

      _httpClient.BaseAddress = new Uri(AcmeServerUrl);
    }
    catch (Exception ex)
    {
      throw new Exception("Failed to load ACME directory", ex);
    }
  }

  /// <summary>
  /// Create new account met private key.
  /// </summary>
  public async Task<Account> CreateAccountAsync(byte[] privateKeyBytes)
  {
    // Generate EC P-256 private key JWK (voor nu placeholder)
    string privateKeyJwk = GeneratePrivateKeys(privateKeyBytes);

    var jwsHeader = new JwsHeaderExtensions
    {
      Alg = "ES256",
      Kid = AcmeServerUrl,
      Url = $"{AcmeServerUrl}/new-account"
    };

    return await CreateAccountWithJwsAsync(jwsHeader, privateKeyJwk)
      .ConfigureAwait(false);
  }

  /// <summary>
  /// Generate random EC P-256 private key.
  /// </summary>
  public async Task<Account> CreateAccountAsync()
  {
    using var rng = RandomNumberGenerator.Create();
    byte[] privateKey = new byte[32]; // P-256 is 32 bytes
    rng.GetBytes(privateKey);

    return await CreateAccountAsync(privateKey).ConfigureAwait(false);
  }

  /// <summary>
  /// Generate random RSA private key (2048 bits).
  /// </summary>
  public async Task<Account> CreateAccountWithRsaAsync()
  {
    using var rsa = RSA.Create(2048);
    byte[] privateKeyDer = EncodePrivateKey(rsa.ExportRSAPrivateKey());

    return await CreateAccountAsync(privateKeyDer).ConfigureAwait(false);
  }

  private string GeneratePrivateKeys(byte[] privateKeyBytes)
  {
    // Placeholder - echte JWK generatie met BouncyCastle of Microsoft.IdentityModel
    throw new NotImplementedException(
      "JWK generation vereist BouncyCastle NuGet package voor volledige ondersteuning.");
  }

  /// <summary>
  /// Request authorization for domain.
  /// </summary>
  public async Task<Authorization> RequestAuthorizationAsync(string domain)
  {
    var jwsHeader = CreateJwsHeader();

    await using var requestContent =
      new StringContent(JwtHelper.Encode($"{{\"identifier\":{{\"value\":\"{domain}\"}}}}"), System.Text.Encoding.UTF8,
        "application/json")
      {
        Headers =
        {
          ContentType = new MediaTypeWithQualityHeaderValue("application/jose+json")
        }
      };

    var response = await _httpClient.PostAsync(string.Empty, requestContent).ConfigureAwait(false);

    if (!response.IsSuccessStatusCode)
    {
      throw new AcmeException($"Failed to request authorization: {response.StatusCode}");
    }

    // Parse authorization from Location header
    string authzUrl = ExtractAuthorizationUrl(response.Headers.Location?.AbsoluteUri);

    var responseContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
    var authorization = JsonSerializer.Deserialize<Authorization>(responseContent)!;

    Authorization = authorization;
    return authorization;
  }

  /// <summary>
  /// Get authorization for domain (if already requested).
  /// </summary>
  public async Task<Authorization> RequestAuthorizationForDomainAsync(string domain)
  {
    // Try to get from storage first, then request if not found
    var account = Account;

    // Parse domain from identifier
    string? authorizationId = await GenerateAuthorizationId(account!.Id, domain);

    try
    {
      var authz = await GetAuthorizationAsync(authorizationId).ConfigureAwait(false);

      if (authz.Status != "valid")
      {
        throw new InvalidOperationException($"Authorization for {domain} not valid: {authz.Status}");
      }

      Authorization = authz;
      return authz;
    }
    catch
    {
      // Authorization doesn't exist yet - request it
      return await RequestAuthorizationAsync(domain).ConfigureAwait(false);
    }
  }

  /// <summary>
  /// Validate challenge en wacht tot status "valid" (met retry).
  /// </summary>
  public async Task<Challenge> WaitForChallengeSuccessAsync(string challId, ChallengeType type)
  {
    var challenge = await GetChallengeAsync(challId).ConfigureAwait(false);

    if (challenge.Status == "valid")
    {
      return challenge;
    }

    // Set status via storage interface
    challenge.Status = "pending";
    await _storage.SetChallengeStatusAsync(challId, ChallengeStatus.Pending);

    // Poll voor succesvol validation met retry
    int attempts = 0;

    while (challenge.Status != "valid" && challenge.Status != "invalid")
    {
      if (attempts++ >= _retryPolicy.MaxAttempts)
      {
        throw new AcmeException($"Challenge {challId} failed after {_retryPolicy.MaxAttempts} attempts");
      }

      await Task.Delay(2000); // Poll cada 2 seconden

      challenge = await GetChallengeAsync(challId).ConfigureAwait(false);
    }

    return challenge;
  }

  /// <summary>
  /// Provisioneer HTTP-01 challenge.
  /// </summary>
  public async Task<string> ProvisionHttpChallengeAsync(Challenge challenge, Authorization authz)
  {
    if (challenge.Type != "http-01")
    {
      throw new ArgumentException($"Expected http-01 challenge, got: {challenge.Type}");
    }

    var url = $"{AcmeServerUrl}/well-known/acme-challenge/{challenge.Token ?? ""}";

    // Set challenge status via storage
    challenge.Status = "pending";
    await _storage.SetChallengeStatusAsync(challenge.Id, ChallengeStatus.Pending);

    // Store expected value in memory (extern app schrijft naar URL)
    var expectedValue = JwtHelper.Encode(challenge.ExpectedValue ?? string.Empty);

    return url;
  }

  /// <summary>
  /// Provisioneer DNS-01 challenge.
  /// </summary>
  public async Task<string> ProvisionDnsChallengeAsync(Challenge challenge, Authorization authz)
  {
    if (challenge.Type != "dns-01")
    {
      throw new ArgumentException($"Expected dns-01 challenge, got: {challenge.Type}");
    }

    // Generate validation domain (e.g., _acme-challenge.example.com)
    string validationDomain = await BuildValidationDomainAsync(authz.Identifier).ConfigureAwait(false);

    // Calculate key authorization digest voor TXT record
    byte[] digestBytes = ComputeKeyAuthorizationDigest();
    string digestBase64 = JwtHelper.Encode(digestBytes);

    // Store in storage (MongoDB/disk)
    await _storage.SetDnsRecordAsync(validationDomain, digestBase64).ConfigureAwait(false);

    challenge.ValidationDomain = validationDomain;
    challenge.Token = digestBase64;
    challenge.ExpectedValue = digestBase64;

    return digestBase64;
  }

  /// <summary>
  /// Provisioneer TLS-ALPN-01 challenge.
  /// </summary>
  public async Task<string> ProvisionTlsAlpnChallengeAsync(Challenge challenge, Authorization authz)
  {
    if (challenge.Type != "tls-alpn-01")
    {
      throw new ArgumentException($"Expected tls-alpn-01 challenge, got: {challenge.Type}");
    }

    // Generate self-signed cert voor TLS-ALPN validation
    byte[] certBytes = GenerateTlsAlpnCertificate(authz.Identifier);

    // Store cert in storage
    await _storage.SaveCertificateAsync(authz.Identifier, certBytes, Array.Empty<byte>()).ConfigureAwait(false);

    return "TLS ALPN challenge ready - configure server to negotiate acme-tls/1";
  }

  /// <summary>
  /// Submit validated challenge.
  /// </summary>
  public async Task SubmitChallengeAsync(string challId)
  {
    await using var content = new StringContent("{}")
    {
      Headers =
      {
        ContentType = new MediaTypeWithQualityHeaderValue("application/jose+json")
      }
    };

    // Construct challenge URL from authz and chall ID
    string? challengeUrl = null;
    if (Authorization != null)
    {
      challengeUrl = $"{AcmeServerUrl}/authz/{Authorization.Id}/chall/{challId}";
    }

    var response = await _httpClient.PostAsync(challengeUrl, content).ConfigureAwait(false);

    if (!response.IsSuccessStatusCode)
    {
      throw new AcmeException($"Failed to submit challenge: {response.StatusCode}");
    }
  }

  /// <summary>
  /// Get certificate bundle for domain.
  /// </summary>
  public async Task<string> GetCertificateAsync(string authzId)
  {
    var response = await _httpClient.GetAsync(
        $"{AcmeServerUrl}/authz/{authzId}")
      .ConfigureAwait(false);

    if (!response.IsSuccessStatusCode)
    {
      throw new AcmeException($"Failed to get certificate: {response.StatusCode}");
    }

    return await response.Content.ReadAsStringAsync().ConfigureAwait(false);
  }

  /// <summary>
  /// Revoke certificate.
  /// </summary>
  public async Task RevokeCertificateAsync(byte[] certificate, Account account)
  {
    // Calculate SHA-256 digest van cert voor revocation
    using var sha256 = SHA256.Create();
    byte[] digest = sha256.ComputeHash(certificate);

    string postJson = $"{{\"certificate\":\"{Convert.ToBase64String(digest)}\",\"revokeReason\":0}}";

    await using var content = new StringContent(postJson, System.Text.Encoding.UTF8, "application/json")
    {
      Headers =
      {
        ContentType = new MediaTypeWithQualityHeaderValue("application/jose+json")
      }
    };

    // Sign en post revoke request
    throw new NotImplementedException("Certificate revocation - requires JWS signing");
  }

  /// <summary>
  /// Deactivate account.
  /// </summary>
  public async Task DeactivateAccountAsync()
  {
    var response = await _httpClient.PostAsync(
        $"{AcmeServerUrl}/acct/{_account!.Id}", new StringContent("{}"))
      .ConfigureAwait(false);

    if (!response.IsSuccessStatusCode)
    {
      throw new AcmeException($"Failed to deactivate account: {response.StatusCode}");
    }
  }

  /// <summary>
  /// Deactivate authorization.
  /// </summary>
  public async Task DeactivateAuthorizationAsync()
  {
    var response = await _httpClient.PostAsync(
        $"{AcmeServerUrl}/acme/authz/{Authorization!.Id}", new StringContent("{}"))
      .ConfigureAwait(false);

    if (!response.IsSuccessStatusCode)
    {
      throw new AcmeException($"Failed to deactivate authorization: {response.StatusCode}");
    }
  }

  /// <summary>
  /// Bereken SHA-256 digest van key authorization.
  /// </summary>
  private byte[] ComputeKeyAuthorizationDigest()
  {
    // RFC 8555 §3.1: HMAC_SHA256(account_key, authz_id)
    throw new NotImplementedException("HMAC computation requires account key storage");
  }

  /// <summary>
  /// Generate self-signed cert voor TLS-ALPN.
  /// </summary>
  private byte[] GenerateTlsAlpnCertificate(string domainName)
  {
    // Create certificate met:
    // - subjectAltName containing domain
    // - critical acmeIdentifier extension (OID 1.3.6.1.5.5.7.1.31)

    throw new NotImplementedException("TLS ALPN certificate generation");
  }

  /// <summary>
  /// Generate authorization ID.
  /// </summary>
  private async Task<string?> GenerateAuthorizationId(string accountId, string domain)
  {
    var authz = await RequestAuthorizationForDomainAsync(domain).ConfigureAwait(false);
    return authz.Id;
  }

  /// <summary>
  /// Build validation domain voor DNS challenge.
  /// </summary>
  private async Task<string> BuildValidationDomainAsync(string identifier)
  {
    var parts = identifier.Split('.');

    // Voor wildcard: _acme-challenge.<subdomain>.<base_domain>
    // Voor non-wildcard: _acme-challenge.<full_domain>
    string baseDomain = identifier.Length > 20 ? parts[^1] : identifier;
    string validationSubdomain = "_acme-challenge";

    return $"{validationSubdomain}.{identifier}";
  }

  /// <summary>
  /// Create JWS header voor ACME calls.
  /// </summary>
  private JwsHeaderExtensions CreateJwsHeader()
  {
    if (_account == null)
    {
      throw new InvalidOperationException("Account not loaded yet");
    }

    // Load nonce van directory (vereist bij ACME v2)
    var response = await _httpClient.GetAsync("/new-nonce").ConfigureAwait(false);
    string? nonce = null;
    if (response.IsSuccessStatusCode)
    {
      string nonceContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
      nonce = JsonSerializer.Deserialize<string>(nonceContent);
    }

    return new JwsHeaderExtensions
    {
      Alg = "ES256",
      Kid = $"{AcmeServerUrl}/acme/acct/{_account.Id}",
      Nonce = nonce,
      Url = _httpClient.BaseAddress.ToString() ?? string.Empty
    };
  }

  private string ExtractAuthorizationUrl(string? locationUri)
  {
    if (locationUri == null)
    {
      throw new InvalidOperationException("Location header missing from ACME response");
    }

    return locationUri;
  }

  public void Dispose()
  {
    _httpClient?.Dispose();
  }
}
