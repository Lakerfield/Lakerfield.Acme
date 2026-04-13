using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Lakerfield.Acme.Models;

namespace Lakerfield.Acme;

/// <summary>
/// ACME client for communicating with Let's Encrypt (and other RFC 8555 compatible servers).
/// Standalone library without DI dependencies — the host application controls all logic.
/// </summary>
public class LakerfieldAcmeClient : IDisposable
{
  private readonly HttpClient _httpClient;
  private readonly IAcmeStorage _storage;
  private readonly AcmeRetryConfig _retryPolicy;

  private AcmeDirectory? _directory;
  private ECDsa? _accountKey;
  private string? _nonce;
  private Account? _account;

  private static readonly JsonSerializerOptions _jsonOptions = new()
  {
    PropertyNameCaseInsensitive = true,
    WriteIndented = false,
  };

  /// <summary>
  /// ACME directory URL (default: Let's Encrypt production)
  /// </summary>
  public string AcmeServerUrl { get; set; } = "https://acme-v02.api.letsencrypt.org/directory";

  /// <summary>
  /// Currently loaded ACME account.
  /// </summary>
  public Account? Account => _account;

  /// <summary>
  /// Parsed ACME directory with endpoint URLs.
  /// </summary>
  public AcmeDirectory? Directory => _directory;

  public LakerfieldAcmeClient(HttpClient httpClient, IAcmeStorage storage, AcmeRetryConfig? retryPolicy = null)
  {
    _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
    _storage = storage ?? throw new ArgumentNullException(nameof(storage));
    _retryPolicy = retryPolicy ?? RetryHelper.DefaultRetryPolicy;

    _httpClient.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("Lakerfield.Acme", "1.0"));
    _httpClient.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("DotNet", Environment.Version.ToString()));
  }

  /// <summary>
  /// Factory overload without an explicit HttpClient — uses a default HttpClient instance.
  /// </summary>
  public LakerfieldAcmeClient(IAcmeStorage storage, AcmeRetryConfig? retryPolicy = null)
    : this(new HttpClient(), storage, retryPolicy)
  {
  }

  // ─── Directory & Nonce ───────────────────────────────────────────────────

  /// <summary>
  /// Loads the ACME directory endpoint and parses the endpoint URLs.
  /// Must be called before using any other client methods.
  /// </summary>
  public async Task LoadDirectoryAsync()
  {
    var response = await _httpClient.GetAsync(AcmeServerUrl).ConfigureAwait(false);

    if (!response.IsSuccessStatusCode)
      throw new AcmeException($"Failed to load ACME directory from {AcmeServerUrl}: {response.StatusCode}");

    var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
    _directory = JsonSerializer.Deserialize<AcmeDirectory>(content, _jsonOptions)
      ?? throw new AcmeException("Failed to parse ACME directory response");

    // Extract a nonce from the response if present
    if (response.Headers.TryGetValues("Replay-Nonce", out var nonceValues))
    {
      foreach (var nonce in nonceValues)
      {
        _nonce = nonce;
        break;
      }
    }
  }

  /// <summary>
  /// Fetches a new nonce from the ACME server (HEAD request on the newNonce endpoint).
  /// </summary>
  private async Task<string> GetNonceAsync()
  {
    if (_directory == null)
      throw new InvalidOperationException("Directory not loaded. Call LoadDirectoryAsync() first.");

    var response = await _httpClient.SendAsync(
      new HttpRequestMessage(HttpMethod.Head, _directory.NewNonce)).ConfigureAwait(false);

    if (response.Headers.TryGetValues("Replay-Nonce", out var values))
    {
      foreach (var nonce in values)
        return nonce;
    }

    throw new AcmeException("ACME server did not return a Replay-Nonce header");
  }

  /// <summary>
  /// Returns the current nonce (reuses the cached one or fetches a new one).
  /// </summary>
  private async Task<string> ConsumeNonceAsync()
  {
    if (_nonce != null)
    {
      var n = _nonce;
      _nonce = null;
      return n;
    }
    return await GetNonceAsync().ConfigureAwait(false);
  }

  // ─── Account management ──────────────────────────────────────────────────

  /// <summary>
  /// Generates a new EC P-256 key pair and stores the private key.
  /// Returns the PKCS#8 DER-encoded private key bytes.
  /// </summary>
  public byte[] GenerateAccountKey()
  {
    _accountKey?.Dispose();
    _accountKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    return _accountKey.ExportPkcs8PrivateKey();
  }

  /// <summary>
  /// Loads an existing EC P-256 private key (PKCS#8 DER-encoded).
  /// </summary>
  public void LoadAccountKey(byte[] pkcs8PrivateKey)
  {
    _accountKey?.Dispose();
    _accountKey = ECDsa.Create();
    _accountKey.ImportPkcs8PrivateKey(pkcs8PrivateKey, out _);
  }

  /// <summary>
  /// Creates a new ACME account with a generated EC P-256 key.
  /// An email address can optionally be provided for notifications.
  /// </summary>
  /// <param name="email">Optional email address for Let's Encrypt notifications</param>
  /// <param name="termsOfServiceAgreed">True to agree to the Terms of Service (required by Let's Encrypt)</param>
  /// <returns>The created Account object with URL</returns>
  public async Task<Account> CreateAccountAsync(string? email = null, bool termsOfServiceAgreed = true)
  {
    EnsureDirectoryLoaded();
    EnsureAccountKeyLoaded();

    var payload = new Dictionary<string, object>
    {
      ["termsOfServiceAgreed"] = termsOfServiceAgreed,
    };

    if (email != null)
      payload["contact"] = new[] { $"mailto:{email}" };

    var payloadJson = JsonSerializer.Serialize(payload, _jsonOptions);
    var nonce = await ConsumeNonceAsync().ConfigureAwait(false);
    var jwsBody = JwtHelper.CreateJwsWithJwk(_accountKey!, nonce, _directory!.NewAccount, payloadJson);

    var response = await PostJwsAsync(_directory.NewAccount, jwsBody).ConfigureAwait(false);

    var accountJson = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
    var account = JsonSerializer.Deserialize<Account>(accountJson, _jsonOptions)
      ?? throw new AcmeException("Failed to parse account response");

    // Account URL is in the Location header
    account.Url = response.Headers.Location?.AbsoluteUri
      ?? throw new AcmeException("ACME server did not return account URL in Location header");
    account.Id = account.Url;

    // Store the nonce for the next request
    ExtractNonce(response);

    _account = account;
    return account;
  }

  /// <summary>
  /// Loads an existing ACME account based on an account URL and private key.
  /// </summary>
  /// <param name="accountUrl">Account URL (e.g. https://acme-v02.api.letsencrypt.org/acme/acct/123)</param>
  /// <param name="pkcs8PrivateKey">PKCS#8 DER-encoded private key</param>
  public async Task<Account> LoadAccountAsync(string accountUrl, byte[] pkcs8PrivateKey)
  {
    EnsureDirectoryLoaded();
    LoadAccountKey(pkcs8PrivateKey);

    // POST-as-GET to retrieve account info
    var nonce = await ConsumeNonceAsync().ConfigureAwait(false);
    var jwsBody = JwtHelper.CreateJwsWithKid(_accountKey!, accountUrl, nonce, accountUrl, null);

    var response = await PostJwsAsync(accountUrl, jwsBody).ConfigureAwait(false);

    var accountJson = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
    var account = JsonSerializer.Deserialize<Account>(accountJson, _jsonOptions)
      ?? throw new AcmeException("Failed to parse account response");

    account.Url = accountUrl;
    account.Id = accountUrl;

    ExtractNonce(response);
    _account = account;
    return account;
  }

  // ─── Order management ────────────────────────────────────────────────────

  /// <summary>
  /// Creates a new certificate order for one or more domains.
  /// </summary>
  /// <param name="domains">List of domain names (e.g. ["example.com", "www.example.com"])</param>
  /// <returns>AcmeOrder with authorization URLs</returns>
  public Task<AcmeOrder> CreateOrderAsync(params string[] domains)
    => CreateOrderAsync(profile: null, domains);

  /// <summary>
  /// Creates a new certificate order for one or more domains using the specified certificate profile.
  /// </summary>
  /// <param name="profile">
  /// Optional certificate profile name (e.g. "classic", "shortlived").
  /// Must be one of the profiles advertised in <see cref="AcmeDirectory.Meta"/>.
  /// Pass <c>null</c> to use the server default.
  /// </param>
  /// <param name="domains">List of domain names (e.g. ["example.com", "www.example.com"])</param>
  /// <returns>AcmeOrder with authorization URLs</returns>
  public async Task<AcmeOrder> CreateOrderAsync(string? profile, params string[] domains)
  {
    EnsureDirectoryLoaded();
    EnsureAccountLoaded();

    var actualIdentifiers = new List<Dictionary<string, string>>();
    foreach (var domain in domains)
    {
      actualIdentifiers.Add(new Dictionary<string, string>
      {
        ["type"] = "dns",
        ["value"] = domain,
      });
    }

    object payload = profile != null
      ? new { identifiers = actualIdentifiers, profile }
      : new { identifiers = actualIdentifiers };
    var payloadJson = JsonSerializer.Serialize(payload, _jsonOptions);
    var nonce = await ConsumeNonceAsync().ConfigureAwait(false);
    var jwsBody = JwtHelper.CreateJwsWithKid(_accountKey!, _account!.Url, nonce, _directory!.NewOrder, payloadJson);

    var response = await PostJwsAsync(_directory.NewOrder, jwsBody).ConfigureAwait(false);

    var orderJson = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
    var order = JsonSerializer.Deserialize<AcmeOrder>(orderJson, _jsonOptions)
      ?? throw new AcmeException("Failed to parse order response");

    order.Url = response.Headers.Location?.AbsoluteUri ?? string.Empty;

    ExtractNonce(response);
    return order;
  }

  /// <summary>
  /// Retrieves the current status of an order.
  /// </summary>
  public async Task<AcmeOrder> GetOrderAsync(string orderUrl)
  {
    EnsureAccountLoaded();

    var nonce = await ConsumeNonceAsync().ConfigureAwait(false);
    var jwsBody = JwtHelper.CreateJwsWithKid(_accountKey!, _account!.Url, nonce, orderUrl, null);

    var response = await PostJwsAsync(orderUrl, jwsBody).ConfigureAwait(false);

    var orderJson = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
    var order = JsonSerializer.Deserialize<AcmeOrder>(orderJson, _jsonOptions)
      ?? throw new AcmeException("Failed to parse order response");

    order.Url = orderUrl;
    ExtractNonce(response);
    return order;
  }

  // ─── Authorization & Challenge ───────────────────────────────────────────

  /// <summary>
  /// Retrieves an authorization from the ACME server.
  /// </summary>
  public async Task<Authorization> GetAuthorizationAsync(string authzUrl)
  {
    EnsureAccountLoaded();

    var nonce = await ConsumeNonceAsync().ConfigureAwait(false);
    var jwsBody = JwtHelper.CreateJwsWithKid(_accountKey!, _account!.Url, nonce, authzUrl, null);

    var response = await PostJwsAsync(authzUrl, jwsBody).ConfigureAwait(false);

    var authzJson = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
    var authz = JsonSerializer.Deserialize<Authorization>(authzJson, _jsonOptions)
      ?? throw new AcmeException("Failed to parse authorization response");

    authz.Url = authzUrl;

    ExtractNonce(response);
    return authz;
  }

  /// <summary>
  /// Computes the key authorization for a challenge token.
  /// keyAuthorization = token + "." + base64url(SHA256(canonicalJwkJson))
  /// </summary>
  public string GetKeyAuthorization(string token)
  {
    EnsureAccountKeyLoaded();
    return JwtHelper.ComputeKeyAuthorization(token, _accountKey!);
  }

  /// <summary>
  /// Computes the HTTP-01 challenge value (= key authorization).
  /// This value must be served at http://&lt;domain&gt;/.well-known/acme-challenge/&lt;token&gt;
  /// </summary>
  public string GetHttpChallengeValue(string token)
  {
    return GetKeyAuthorization(token);
  }

  /// <summary>
  /// Computes the DNS-01 challenge value (= base64url(SHA256(keyAuthorization))).
  /// This value must be set as a TXT record on _acme-challenge.&lt;domain&gt;
  /// </summary>
  public string GetDnsChallengeValue(string token)
  {
    var keyAuth = GetKeyAuthorization(token);
    return JwtHelper.ComputeDns01Value(keyAuth);
  }

  /// <summary>
  /// Generates the DNS-01 validation domain name for a given domain.
  /// For wildcard *.example.com this is _acme-challenge.example.com.
  /// </summary>
  public static string GetDnsValidationDomain(string domain)
  {
    // Strip wildcard prefix if present
    var baseDomain = domain.StartsWith("*.") ? domain[2..] : domain;
    return $"_acme-challenge.{baseDomain}";
  }

  /// <summary>
  /// Generates the DNS-01 forward prefix validation domain name for a given domain.
  /// For www.example.com this is www-example-com
  /// For wildcard *.example.com this is example-com
  /// </summary>
  public static string GetDnsValidationForwardLabel(string domain)
  {
    // Strip wildcard prefix if present
    var baseDomain = domain.StartsWith("*.") ? domain[2..] : domain;
    return baseDomain
      .Replace(".", "-")
      .Replace("--", "-")
      .Replace("--", "-")
      .Trim('-');
  }

  /// <summary>
  /// Generates a self-signed TLS-ALPN-01 certificate for a domain as per RFC 8737.
  /// The certificate contains the acmeIdentifier extension (OID 1.3.6.1.5.5.7.1.31)
  /// with the SHA-256 digest of the key authorization.
  /// </summary>
  public X509Certificate2 GenerateTlsAlpnCertificate(string domain, string token)
  {
    EnsureAccountKeyLoaded();

    var keyAuth = GetKeyAuthorization(token);
    var keyAuthHash = SHA256.HashData(Encoding.UTF8.GetBytes(keyAuth));

    using var certKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    var req = new CertificateRequest($"CN={domain}", certKey, HashAlgorithmName.SHA256);

    // Subject Alternative Name with the domain
    var sanBuilder = new SubjectAlternativeNameBuilder();
    sanBuilder.AddDnsName(domain);
    req.CertificateExtensions.Add(sanBuilder.Build());

    // acmeIdentifier extension (OID 1.3.6.1.5.5.7.1.31) as per RFC 8737 §3
    // Value: DER OCTET STRING with SHA-256 of key authorization
    var extValue = new byte[34];
    extValue[0] = 0x04; // OCTET STRING tag
    extValue[1] = 0x20; // length 32
    keyAuthHash.CopyTo(extValue, 2);
    req.CertificateExtensions.Add(new X509Extension("1.3.6.1.5.5.7.1.31", extValue, critical: true));

    var notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
    var notAfter = DateTimeOffset.UtcNow.AddDays(1);

    return req.CreateSelfSigned(notBefore, notAfter);
  }

  /// <summary>
  /// Notifies the ACME server that the challenge is ready for validation.
  /// Call this after provisioning the challenge (HTTP file, DNS record, TLS certificate).
  /// </summary>
  public async Task ValidateChallengeAsync(string challengeUrl)
  {
    EnsureAccountLoaded();

    var nonce = await ConsumeNonceAsync().ConfigureAwait(false);
    // Empty JSON payload ({}) to indicate we are ready
    var payloadJson = "{}";
    var jwsBody = JwtHelper.CreateJwsWithKid(_accountKey!, _account!.Url, nonce, challengeUrl, payloadJson);

    var response = await PostJwsAsync(challengeUrl, jwsBody).ConfigureAwait(false);
    ExtractNonce(response);
  }

  /// <summary>
  /// Waits until a challenge reaches the status "valid" or "invalid".
  /// Polls with exponential backoff.
  /// </summary>
  public async Task<Challenge> WaitForChallengeValidAsync(string challengeUrl, CancellationToken cancellationToken = default)
  {
    EnsureAccountLoaded();

    var delay = TimeSpan.FromSeconds(_retryPolicy.InitialDelaySeconds);
    var maxDelay = TimeSpan.FromSeconds(_retryPolicy.MaxDelaySeconds);

    for (int attempt = 0; attempt < _retryPolicy.MaxAttempts; attempt++)
    {
      await Task.Delay(delay, cancellationToken).ConfigureAwait(false);

      var nonce = await ConsumeNonceAsync().ConfigureAwait(false);
      var jwsBody = JwtHelper.CreateJwsWithKid(_accountKey!, _account!.Url, nonce, challengeUrl, null);

      var response = await PostJwsAsync(challengeUrl, jwsBody).ConfigureAwait(false);
      ExtractNonce(response);

      var challengeJson = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
      var challenge = JsonSerializer.Deserialize<Challenge>(challengeJson, _jsonOptions)
        ?? throw new AcmeException("Failed to parse challenge response");
      challenge.Url = challengeUrl;

      if (challenge.Status == "valid")
        return challenge;

      if (challenge.Status == "invalid")
        throw new AcmeException($"Challenge {challengeUrl} failed: {challenge.ErrorMessage ?? "unknown error"}");

      // Exponential backoff
      delay = TimeSpan.FromSeconds(Math.Min(delay.TotalSeconds * _retryPolicy.ExponentialBase, maxDelay.TotalSeconds));
    }

    throw new AcmeException($"Challenge {challengeUrl} did not become valid after {_retryPolicy.MaxAttempts} attempts");
  }

  // ─── Certificate issuance ────────────────────────────────────────────────

  /// <summary>
  /// Waits until an order reaches the status "ready" (all authorizations are valid).
  /// </summary>
  public async Task<AcmeOrder> WaitForOrderReadyAsync(string orderUrl, CancellationToken cancellationToken = default)
  {
    var delay = TimeSpan.FromSeconds(_retryPolicy.InitialDelaySeconds);
    var maxDelay = TimeSpan.FromSeconds(_retryPolicy.MaxDelaySeconds);

    for (int attempt = 0; attempt < _retryPolicy.MaxAttempts; attempt++)
    {
      var order = await GetOrderAsync(orderUrl).ConfigureAwait(false);

      if (order.Status == "ready" || order.Status == "valid")
        return order;

      if (order.Status == "invalid")
        throw new AcmeException($"Order {orderUrl} is in invalid state");

      await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
      delay = TimeSpan.FromSeconds(Math.Min(delay.TotalSeconds * _retryPolicy.ExponentialBase, maxDelay.TotalSeconds));
    }

    throw new AcmeException($"Order {orderUrl} did not become ready after {_retryPolicy.MaxAttempts} attempts");
  }

  /// <summary>
  /// Finalizes an order by submitting a CSR.
  /// Automatically generates a new EC P-256 key pair for the certificate.
  /// </summary>
  /// <param name="order">The order to finalize</param>
  /// <param name="domains">Domain names for the certificate (SAN)</param>
  /// <param name="certKey">Optional EC key pair for the certificate; a new key pair is generated when null</param>
  /// <returns>Updated order with certificate URL</returns>
  public async Task<(AcmeOrder Order, byte[] CertificatePrivateKey)> FinalizeOrderAsync(
    AcmeOrder order,
    string[] domains,
    ECDsa? certKey = null)
  {
    EnsureAccountLoaded();

    var ownCertKey = certKey == null;
    certKey ??= ECDsa.Create(ECCurve.NamedCurves.nistP256);

    try
    {
      // Generate CSR
      var csrBytes = GenerateCsr(domains, certKey);
      var csrB64 = JwtHelper.Encode(csrBytes);

      var payload = new { csr = csrB64 };
      var payloadJson = JsonSerializer.Serialize(payload, _jsonOptions);
      var nonce = await ConsumeNonceAsync().ConfigureAwait(false);
      var jwsBody = JwtHelper.CreateJwsWithKid(_accountKey!, _account!.Url, nonce, order.Finalize, payloadJson);

      var response = await PostJwsAsync(order.Finalize, jwsBody).ConfigureAwait(false);
      ExtractNonce(response);

      var orderJson = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
      var updatedOrder = JsonSerializer.Deserialize<AcmeOrder>(orderJson, _jsonOptions)
        ?? throw new AcmeException("Failed to parse finalize response");

      updatedOrder.Url = order.Url;

      var certPrivateKey = certKey.ExportPkcs8PrivateKey();
      return (updatedOrder, certPrivateKey);
    }
    finally
    {
      if (ownCertKey)
        certKey.Dispose();
    }
  }

  /// <summary>
  /// Waits until an order has been processed and its certificate is ready to download.
  /// </summary>
  public async Task<AcmeOrder> WaitForOrderValidAsync(string orderUrl, CancellationToken cancellationToken = default)
  {
    var delay = TimeSpan.FromSeconds(_retryPolicy.InitialDelaySeconds);
    var maxDelay = TimeSpan.FromSeconds(_retryPolicy.MaxDelaySeconds);

    for (int attempt = 0; attempt < _retryPolicy.MaxAttempts; attempt++)
    {
      var order = await GetOrderAsync(orderUrl).ConfigureAwait(false);

      if (order.Status == "valid" && order.Certificate != null)
        return order;

      if (order.Status == "invalid")
        throw new AcmeException($"Order {orderUrl} is in invalid state");

      await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
      delay = TimeSpan.FromSeconds(Math.Min(delay.TotalSeconds * _retryPolicy.ExponentialBase, maxDelay.TotalSeconds));
    }

    throw new AcmeException($"Order {orderUrl} did not become valid after {_retryPolicy.MaxAttempts} attempts");
  }

  /// <summary>
  /// Downloads the certificate from a completed order.
  /// </summary>
  /// <returns>PEM-encoded certificate chain</returns>
  public async Task<string> DownloadCertificateAsync(AcmeOrder order)
  {
    if (order.Certificate == null)
      throw new InvalidOperationException("Order does not have a certificate URL yet. Is the order status 'valid'?");

    EnsureAccountLoaded();

    var nonce = await ConsumeNonceAsync().ConfigureAwait(false);
    var jwsBody = JwtHelper.CreateJwsWithKid(_accountKey!, _account!.Url, nonce, order.Certificate, null);

    var response = await PostJwsAsync(order.Certificate, jwsBody).ConfigureAwait(false);
    ExtractNonce(response);

    return await response.Content.ReadAsStringAsync().ConfigureAwait(false);
  }

  // ─── Certificate revocation ──────────────────────────────────────────────

  /// <summary>
  /// Revokes a certificate as per RFC 8555 §7.6.
  /// </summary>
  /// <param name="certDer">DER-encoded certificate</param>
  /// <param name="reason">Optional revocation reason code (RFC 5280 CRL reason codes)</param>
  public async Task RevokeCertificateAsync(byte[] certDer, int? reason = null)
  {
    EnsureDirectoryLoaded();
    EnsureAccountLoaded();

    var certB64 = JwtHelper.Encode(certDer);
    object payload = reason.HasValue
      ? new { certificate = certB64, reason = reason.Value }
      : (object)new { certificate = certB64 };

    var payloadJson = JsonSerializer.Serialize(payload, _jsonOptions);
    var nonce = await ConsumeNonceAsync().ConfigureAwait(false);
    var jwsBody = JwtHelper.CreateJwsWithKid(_accountKey!, _account!.Url, nonce, _directory!.RevokeCert, payloadJson);

    var response = await PostJwsAsync(_directory.RevokeCert, jwsBody).ConfigureAwait(false);
    ExtractNonce(response);
  }

  // ─── Account deactivation ────────────────────────────────────────────────

  /// <summary>
  /// Deactivates the current account as per RFC 8555 §7.3.6.
  /// </summary>
  public async Task DeactivateAccountAsync()
  {
    EnsureAccountLoaded();

    var payload = new { status = "deactivated" };
    var payloadJson = JsonSerializer.Serialize(payload, _jsonOptions);
    var nonce = await ConsumeNonceAsync().ConfigureAwait(false);
    var jwsBody = JwtHelper.CreateJwsWithKid(_accountKey!, _account!.Url, nonce, _account.Url, payloadJson);

    var response = await PostJwsAsync(_account.Url, jwsBody).ConfigureAwait(false);
    ExtractNonce(response);
    _account = null;
  }

  // ─── Private helpers ─────────────────────────────────────────────────────

  private static byte[] GenerateCsr(string[] domains, ECDsa certKey)
  {
    if (domains.Length == 0)
      throw new ArgumentException("At least one domain name is required", nameof(domains));

    var req = new CertificateRequest($"CN={domains[0]}", certKey, HashAlgorithmName.SHA256);

    var sanBuilder = new SubjectAlternativeNameBuilder();
    foreach (var domain in domains)
      sanBuilder.AddDnsName(domain);

    req.CertificateExtensions.Add(sanBuilder.Build());

    return req.CreateSigningRequest();
  }

  private async Task<HttpResponseMessage> PostJwsAsync(string url, string jwsBody)
  {
    using var content = new StringContent(jwsBody, Encoding.UTF8, "application/jose+json");
    // RFC 8555 §6.2 requires Content-Type to be exactly "application/jose+json" without charset parameter
    content.Headers.ContentType!.CharSet = null;

    var response = await _httpClient.PostAsync(url, content).ConfigureAwait(false);

    if (!response.IsSuccessStatusCode)
    {
      var errorBody = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

      // Attempt to parse the ACME error
      AcmeError? acmeError = null;
      try
      {
        acmeError = JsonSerializer.Deserialize<AcmeError>(errorBody, _jsonOptions);
      }
      catch
      {
        // Ignore parse errors
      }

      var message = acmeError?.Detail ?? errorBody;
      throw new AcmeException($"ACME request to {url} failed ({response.StatusCode}): {message}");
    }

    return response;
  }

  private void ExtractNonce(HttpResponseMessage response)
  {
    if (response.Headers.TryGetValues("Replay-Nonce", out var values))
    {
      foreach (var nonce in values)
      {
        _nonce = nonce;
        break;
      }
    }
  }

  private void EnsureDirectoryLoaded()
  {
    if (_directory == null)
      throw new InvalidOperationException("Directory not loaded. Call LoadDirectoryAsync() first.");
  }

  private void EnsureAccountKeyLoaded()
  {
    if (_accountKey == null)
      throw new InvalidOperationException("Account key not loaded. Call GenerateAccountKey() or LoadAccountKey() first.");
  }

  private void EnsureAccountLoaded()
  {
    EnsureAccountKeyLoaded();
    if (_account == null)
      throw new InvalidOperationException("Account not loaded. Call CreateAccountAsync() or LoadAccountAsync() first.");
  }

  public void Dispose()
  {
    _accountKey?.Dispose();
    _httpClient?.Dispose();
    GC.SuppressFinalize(this);
  }
}
