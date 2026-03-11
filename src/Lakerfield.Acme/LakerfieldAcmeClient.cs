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
/// ACME client voor communicatie met Let's Encrypt (en andere RFC 8555 compatible servers).
/// Losse library zonder DI dependencies - externe app stuurt logica.
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
  /// ACME directory URL (standaard: Let's Encrypt productie)
  /// </summary>
  public string AcmeServerUrl { get; set; } = "https://acme-v02.api.letsencrypt.org/directory";

  /// <summary>
  /// Huidig geladen ACME account.
  /// </summary>
  public Account? Account => _account;

  /// <summary>
  /// Parsed ACME directory met endpoint URLs.
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
  /// Factory methode zonder explicit HttpClient - gebruikt default HttpClient.
  /// </summary>
  public LakerfieldAcmeClient(IAcmeStorage storage, AcmeRetryConfig? retryPolicy = null)
    : this(new HttpClient(), storage, retryPolicy)
  {
  }

  // ─── Directory & Nonce ───────────────────────────────────────────────────

  /// <summary>
  /// Laad ACME directory endpoint en parseer de endpoint URLs.
  /// Moet aangeroepen worden voor het gebruik van de client.
  /// </summary>
  public async Task LoadDirectoryAsync()
  {
    var response = await _httpClient.GetAsync(AcmeServerUrl).ConfigureAwait(false);

    if (!response.IsSuccessStatusCode)
      throw new AcmeException($"Failed to load ACME directory from {AcmeServerUrl}: {response.StatusCode}");

    var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
    _directory = JsonSerializer.Deserialize<AcmeDirectory>(content, _jsonOptions)
      ?? throw new AcmeException("Failed to parse ACME directory response");

    // Extraheer een nonce uit de response als die er is
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
  /// Haal een nieuwe nonce op van de ACME server (HEAD request op newNonce endpoint).
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
  /// Haal de huidige nonce op (hergebruik of vraag een nieuwe op).
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
  /// Genereer een nieuw EC P-256 sleutelpaar en sla de private key op.
  /// Retourneert de PKCS#8 DER-encoded private key bytes.
  /// </summary>
  public byte[] GenerateAccountKey()
  {
    _accountKey?.Dispose();
    _accountKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    return _accountKey.ExportPkcs8PrivateKey();
  }

  /// <summary>
  /// Laad een bestaande EC P-256 private key (PKCS#8 DER-encoded).
  /// </summary>
  public void LoadAccountKey(byte[] pkcs8PrivateKey)
  {
    _accountKey?.Dispose();
    _accountKey = ECDsa.Create();
    _accountKey.ImportPkcs8PrivateKey(pkcs8PrivateKey, out _);
  }

  /// <summary>
  /// Maak een nieuw ACME account aan met een gegenereerde EC P-256 key.
  /// Optioneel kan een email adres opgegeven worden voor notificaties.
  /// </summary>
  /// <param name="email">Optioneel email adres voor Let's Encrypt notificaties</param>
  /// <param name="termsOfServiceAgreed">True om akkoord te gaan met de ToS (vereist door Let's Encrypt)</param>
  /// <returns>Het aangemaakte Account object met URL</returns>
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

    // Account URL zit in de Location header
    account.Url = response.Headers.Location?.AbsoluteUri
      ?? throw new AcmeException("ACME server did not return account URL in Location header");
    account.Id = account.Url;

    // Sla de nonce op voor het volgende request
    ExtractNonce(response);

    _account = account;
    return account;
  }

  /// <summary>
  /// Laad een bestaand ACME account op basis van een account URL en private key.
  /// </summary>
  /// <param name="accountUrl">Account URL (bijv. https://acme-v02.api.letsencrypt.org/acme/acct/123)</param>
  /// <param name="pkcs8PrivateKey">PKCS#8 DER-encoded private key</param>
  public async Task<Account> LoadAccountAsync(string accountUrl, byte[] pkcs8PrivateKey)
  {
    EnsureDirectoryLoaded();
    LoadAccountKey(pkcs8PrivateKey);

    // POST-as-GET om account info op te halen
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
  /// Maak een nieuw certificaatverzoek (order) voor een of meer domeinen.
  /// </summary>
  /// <param name="domains">Lijst van domeinnamen (bijv. ["example.com", "www.example.com"])</param>
  /// <returns>AcmeOrder met authorization URLs</returns>
  public async Task<AcmeOrder> CreateOrderAsync(params string[] domains)
  {
    EnsureDirectoryLoaded();
    EnsureAccountLoaded();

    var actualIdentifiers = new List<Dictionary<string, string>>();
    foreach (var domain in domains)
    {
      actualIdentifiers.Add(new Dictionary<string, string>
      {
        ["type"] = "dns",
        ["value"] = domain.StartsWith("*.") ? domain[2..] : domain,
      });
    }

    var payload = new { identifiers = actualIdentifiers };
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
  /// Haal de huidige status van een order op.
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
  /// Haal een authorization op van de ACME server.
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
  /// Bereken de key authorization voor een challenge token.
  /// keyAuthorization = token + "." + base64url(SHA256(canonicalJwkJson))
  /// </summary>
  public string GetKeyAuthorization(string token)
  {
    EnsureAccountKeyLoaded();
    return JwtHelper.ComputeKeyAuthorization(token, _accountKey!);
  }

  /// <summary>
  /// Bereken de HTTP-01 challenge waarde (= key authorization).
  /// Deze waarde moet beschikbaar zijn op http://&lt;domain&gt;/.well-known/acme-challenge/&lt;token&gt;
  /// </summary>
  public string GetHttpChallengeValue(string token)
  {
    return GetKeyAuthorization(token);
  }

  /// <summary>
  /// Bereken de DNS-01 challenge waarde (= base64url(SHA256(keyAuthorization))).
  /// Deze waarde moet als TXT record op _acme-challenge.&lt;domain&gt; staan.
  /// </summary>
  public string GetDnsChallengeValue(string token)
  {
    var keyAuth = GetKeyAuthorization(token);
    return JwtHelper.ComputeDns01Value(keyAuth);
  }

  /// <summary>
  /// Genereer de DNS-01 validatiedomeinnaam voor een domein.
  /// Voor wildcard *.example.com is dit _acme-challenge.example.com.
  /// </summary>
  public static string GetDnsValidationDomain(string domain)
  {
    // Strip wildcard prefix indien aanwezig
    var baseDomain = domain.StartsWith("*.") ? domain[2..] : domain;
    return $"_acme-challenge.{baseDomain}";
  }

  /// <summary>
  /// Genereer een self-signed TLS-ALPN-01 certificate voor een domein conform RFC 8737.
  /// Het certificaat bevat de acmeIdentifier extensie (OID 1.3.6.1.5.5.7.1.31)
  /// met de SHA-256 digest van de key authorization.
  /// </summary>
  public X509Certificate2 GenerateTlsAlpnCertificate(string domain, string token)
  {
    EnsureAccountKeyLoaded();

    var keyAuth = GetKeyAuthorization(token);
    var keyAuthHash = SHA256.HashData(Encoding.UTF8.GetBytes(keyAuth));

    using var certKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    var req = new CertificateRequest($"CN={domain}", certKey, HashAlgorithmName.SHA256);

    // Subject Alternative Name met het domein
    var sanBuilder = new SubjectAlternativeNameBuilder();
    sanBuilder.AddDnsName(domain);
    req.CertificateExtensions.Add(sanBuilder.Build());

    // acmeIdentifier extensie (OID 1.3.6.1.5.5.7.1.31) conform RFC 8737 §3
    // Waarde: DER OCTET STRING met SHA-256 van key authorization
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
  /// Zeg tegen de ACME server dat de challenge klaar is voor validatie.
  /// Roep dit aan nadat je de challenge provisioned hebt (HTTP bestand, DNS record, TLS cert).
  /// </summary>
  public async Task ValidateChallengeAsync(string challengeUrl)
  {
    EnsureAccountLoaded();

    var nonce = await ConsumeNonceAsync().ConfigureAwait(false);
    // Lege JSON payload ({}) om aan te geven dat we klaar zijn
    var payloadJson = "{}";
    var jwsBody = JwtHelper.CreateJwsWithKid(_accountKey!, _account!.Url, nonce, challengeUrl, payloadJson);

    var response = await PostJwsAsync(challengeUrl, jwsBody).ConfigureAwait(false);
    ExtractNonce(response);
  }

  /// <summary>
  /// Wacht tot een challenge de status "valid" of "invalid" heeft.
  /// Poll elke 2 seconden met exponential backoff.
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
  /// Wacht tot een order de status "ready" heeft (alle authorizations zijn valid).
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
  /// Finaliseer een order door een CSR in te dienen.
  /// Genereert automatisch een nieuw EC P-256 sleutelpaar voor het certificaat.
  /// </summary>
  /// <param name="order">De order om te finaliseren</param>
  /// <param name="domains">Domeinnamen voor het certificaat (SAN)</param>
  /// <param name="certKey">Optioneel EC sleutelpaar voor het certificaat; nieuw sleutelpaar wordt gegenereerd als null</param>
  /// <returns>Updated order met certificate URL</returns>
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
      // Genereer CSR
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
  /// Wacht tot een order is verwerkt en download daarna het certificaat.
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
  /// Download het certificaat van een voltooide order.
  /// </summary>
  /// <returns>PEM-encoded certificaatketen</returns>
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
  /// Revoceer een certificaat conform RFC 8555 §7.6.
  /// </summary>
  /// <param name="certDer">DER-encoded certificaat</param>
  /// <param name="reason">Optionele revocation reason code (RFC 5280 CRL reason codes)</param>
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
  /// Deactiveer het huidige account conform RFC 8555 §7.3.6.
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

      // Probeer ACME error te parsen
      AcmeError? acmeError = null;
      try
      {
        acmeError = JsonSerializer.Deserialize<AcmeError>(errorBody, _jsonOptions);
      }
      catch
      {
        // Negeer parse fouten
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
