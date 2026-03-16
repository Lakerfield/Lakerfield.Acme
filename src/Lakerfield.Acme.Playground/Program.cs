using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Lakerfield.Acme;
using Lakerfield.Acme.Models;
using Lakerfield.Acme.Playground;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

// ─── Lakerfield.Acme Playground ─────────────────────────────────────────────
//
// This example demonstrates the complete ACME workflow:
// 1. Create an account
// 2. Place an order for a domain
// 3. Provision the challenge (HTTP-01)
// 4. Validate the challenge
// 5. Download the certificate
//
// Let's Encrypt staging server: https://acme-staging-v02.api.letsencrypt.org/directory
// Let's Encrypt production server: https://acme-v02.api.letsencrypt.org/directory
//
// NOTE: The minimal ASP.NET Core web app listens on 0.0.0.0:80 for HTTP-01 validation.
// On Linux/macOS, listening on port 80 requires elevated privileges (e.g. sudo or CAP_NET_BIND_SERVICE).
// ─────────────────────────────────────────────────────────────────────────────

var adminEmail = "admin@example.com";
var testDomain = "example.com";
var acmeDomain = "acme.validation-domain.com";

// ─── Minimal ASP.NET Core web app for hosting HTTP-01 challenges ─────────────
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAcmeHttp01Challenge();

// DNS challenge server
builder.Services.AddAcmeDnsServer(options =>
{
  options.BindAddress = IPAddress.Any;
  options.Port = 53;
  options.ZoneName = acmeDomain;
  options.DefaultTtl = 30;
});

var webApp = builder.Build();
webApp.Urls.Add("http://0.0.0.0:80");
webApp.UseAcmeHttp01Challenge();

var tokenStore = webApp.Services.GetRequiredService<AcmeChallengeTokenStore>();
var dnsStore = webApp.Services.GetRequiredService<IAcmeDnsChallengeStore>();

await webApp.StartAsync();

Console.WriteLine("Lakerfield.Acme Playground");
Console.WriteLine("==========================");
Console.WriteLine();

// Use the in-memory storage implementation for this demo
var storage = new InMemoryAcmeStorage();

// Use Let's Encrypt staging for testing (no real certificates issued)
var acmeServerUrl = "https://acme-staging-v02.api.letsencrypt.org/directory";

using var client = new LakerfieldAcmeClient(new HttpClient(), storage);
client.AcmeServerUrl = acmeServerUrl;

Console.WriteLine($"ACME Server: {acmeServerUrl}");
Console.WriteLine();

try
{
  // Step 1: Load the ACME directory
  Console.WriteLine("Step 1: Loading ACME directory...");
  await client.LoadDirectoryAsync();
  Console.WriteLine($"  newAccount: {client.Directory?.NewAccount}");
  Console.WriteLine($"  newOrder:   {client.Directory?.NewOrder}");
  Console.WriteLine($"  newNonce:   {client.Directory?.NewNonce}");
  Console.WriteLine();

  // Step 2: Load an existing account or create a new one
  var keyPath = Path.Combine(Path.GetTempPath(), "acme-account-key.der");
  var accountUrlPath = Path.Combine(Path.GetTempPath(), "acme-account-url.txt");

  Account account;
  if (File.Exists(keyPath) && File.Exists(accountUrlPath))
  {
    Console.WriteLine("Step 2: Loading existing account...");
    var savedKey = await File.ReadAllBytesAsync(keyPath);
    var savedAccountUrl = await File.ReadAllTextAsync(accountUrlPath);
    Console.WriteLine($"  Private key loaded: {keyPath}");
    Console.WriteLine($"  Account URL loaded: {savedAccountUrl}");

    account = await client.LoadAccountAsync(savedAccountUrl, savedKey);
    Console.WriteLine($"  Account loaded: {account.Url}");
    Console.WriteLine($"  Account status: {account.Status}");
  }
  else
  {
    Console.WriteLine("Step 2: Creating new account...");
    var privateKey = client.GenerateAccountKey();
    Console.WriteLine($"  EC P-256 private key generated ({privateKey.Length} bytes)");

    account = await client.CreateAccountAsync(email: adminEmail);
    Console.WriteLine($"  Account created: {account.Url}");
    Console.WriteLine($"  Account status: {account.Status}");

    // Save the private key and account URL for later use
    await File.WriteAllBytesAsync(keyPath, privateKey);
    await File.WriteAllTextAsync(accountUrlPath, account.Url);
    Console.WriteLine($"  Private key saved: {keyPath}");
    Console.WriteLine($"  Account URL saved: {accountUrlPath}");
  }

  Console.WriteLine();

  // Step 3: Create an order for a domain
  var domain = testDomain;
  Console.WriteLine($"Step 3: Creating order for {domain}...");
  var order = await client.CreateOrderAsync(domain);
  Console.WriteLine($"  Order URL: {order.Url}");
  Console.WriteLine($"  Order status: {order.Status}");
  Console.WriteLine($"  Authorizations: {order.Authorizations.Count}");
  Console.WriteLine();

  // Step 4: Process each authorization
  Console.WriteLine("Step 4: Processing authorizations...");
  foreach (var authzUrl in order.Authorizations)
  {
    Console.WriteLine($"  Authorization: {authzUrl}");
    var authz = await client.GetAuthorizationAsync(authzUrl);
    Console.WriteLine($"  Domain: {authz.Identifier}");
    Console.WriteLine($"  Status: {authz.Status}");

    Challenge? httpChallenge = null;
    Challenge? dnsChallenge = null;
    foreach (var challenge in authz.Challenges)
    {
      Console.WriteLine($"    Challenge type: {challenge.Type}, status: {challenge.Status}");
      // Select the HTTP-01 challenge
      if (challenge.Type == "http-01")
        httpChallenge = challenge;

      // Select the DNS-01 challenge
      if (challenge.Type == "dns-01")
        dnsChallenge = challenge;
    }

    if (httpChallenge != null)
    {
      var token = httpChallenge.Token!;
      var keyAuthValue = client.GetHttpChallengeValue(token);
      var challengeUrl = $"http://{authz.Identifier}/.well-known/acme-challenge/{token}";

      Console.WriteLine();
      Console.WriteLine($"  HTTP-01 Challenge:");
      Console.WriteLine($"    Token: {token}");
      Console.WriteLine($"    Key Authorization: {keyAuthValue}");
      Console.WriteLine($"    URL: {challengeUrl}");
      Console.WriteLine();
      Console.WriteLine($"  Token registered on the local web app:");
      Console.WriteLine($"    http://{authz.Identifier}/.well-known/acme-challenge/{token}");
      Console.WriteLine();

      // Register the token with the local web app so the ACME server can fetch it.
      tokenStore.AddToken(token, keyAuthValue);

      Console.WriteLine($"  Validating challenge...");
      await client.ValidateChallengeAsync(httpChallenge.Url!);
      Console.WriteLine($"  Waiting for challenge validation...");
      var validatedChallenge = await client.WaitForChallengeValidAsync(httpChallenge.Url!);
      Console.WriteLine($"  Challenge status: {validatedChallenge.Status}");

      tokenStore.RemoveToken(token);
    }

    // DNS-01 example
    if (dnsChallenge != null)
    {
      var dnsValue = dnsChallenge.Token != null
        ? client.GetDnsChallengeValue(dnsChallenge.Token!)
        : "n/a";
      var dnsDomain = LakerfieldAcmeClient.GetDnsValidationDomain(authz.Identifier);
      var forwardLabel = LakerfieldAcmeClient.GetDnsValidationForwardLabel(authz.Identifier);
      var forwardedTxtRecord = $"{forwardLabel}.{acmeDomain}";
      Console.WriteLine($"  DNS-01 (as alternative):");
      Console.WriteLine($"    TXT record:         {dnsDomain}");
      Console.WriteLine($"    TXT record value:   {dnsValue}");
      Console.WriteLine($"    or CNAME forwarded: {forwardedTxtRecord}");

      // Register the token with the local dns so the ACME server can fetch it.
      dnsStore.SetTxtRecord(
        forwardedTxtRecord,
        dnsValue,
        ttl: 30,
        validFor: TimeSpan.FromMinutes(10));

      Console.WriteLine($"  Validating challenge...");
      await client.ValidateChallengeAsync(dnsChallenge.Url!);
      Console.WriteLine($"  Waiting for challenge validation...");
      var validatedChallenge = await client.WaitForChallengeValidAsync(dnsChallenge.Url!);
      Console.WriteLine($"  Challenge status: {validatedChallenge.Status}");

      dnsStore.RemoveRecord(forwardedTxtRecord);
    }
  }

  Console.WriteLine();
  Console.WriteLine("Step 5: Requesting and downloading certificate...");

  Console.WriteLine("  Waiting for order to become 'ready'...");
  var readyOrder = await client.WaitForOrderReadyAsync(order.Url!);
  Console.WriteLine($"  Order status: {readyOrder.Status}");

  Console.WriteLine("  Finalizing order (submitting CSR)...");
  var (pendingOrder, certPrivateKey) = await client.FinalizeOrderAsync(readyOrder, new[] { domain });
  Console.WriteLine($"  Order status after finalize: {pendingOrder.Status}");

  Console.WriteLine("  Waiting for order to become 'valid'...");
  var validOrder = await client.WaitForOrderValidAsync(pendingOrder.Url!);
  Console.WriteLine($"  Order status: {validOrder.Status}");

  Console.WriteLine("  Downloading certificate...");
  var pem = await client.DownloadCertificateAsync(validOrder);
  Console.WriteLine();
  Console.WriteLine("─── PEM Certificate ────────────────────────────────────────────────────────");
  Console.WriteLine(pem);
  Console.WriteLine("────────────────────────────────────────────────────────────────────────────");
  Console.WriteLine();
  Console.WriteLine("Demo completed successfully!");
}
catch (AcmeException ex)
{
  Console.ForegroundColor = ConsoleColor.Red;
  Console.WriteLine($"ACME Error: {ex.Message}");
  Console.ResetColor();
}
catch (Exception ex)
{
  Console.ForegroundColor = ConsoleColor.Red;
  Console.WriteLine($"Error: {ex.GetType().Name}: {ex.Message}");
  Console.ResetColor();
}
finally
{
  await webApp.StopAsync();
}

// ─── In-Memory Storage implementation ───────────────────────────────────────

/// <summary>
/// Simple in-memory implementation of IAcmeStorage for demo purposes.
/// In production, use MongoDB, disk, or another persistent storage backend.
/// </summary>
class InMemoryAcmeStorage : IAcmeStorage
{
  private readonly Dictionary<string, Lakerfield.Acme.Models.Account> _accounts = new();
  private readonly Dictionary<string, Lakerfield.Acme.Models.Challenge> _challenges = new();
  private readonly Dictionary<string, string> _dnsRecords = new();
  private readonly Dictionary<string, (byte[] cert, byte[] key)> _certificates = new();
  private readonly Dictionary<string, byte[]> _privateKeys = new();

  public Task<Lakerfield.Acme.Models.Account> GetOrCreateAccountAsync(string keyJwk, string serverUrl)
  {
    var key = $"{serverUrl}:{keyJwk}";
    if (!_accounts.TryGetValue(key, out var account))
    {
      account = new Lakerfield.Acme.Models.Account
      {
        Id = Guid.NewGuid().ToString(),
        Url = $"{serverUrl}/acme/acct/{Guid.NewGuid()}",
        Status = "valid",
      };
      _accounts[key] = account;
    }
    return Task.FromResult(account);
  }

  public Task<Lakerfield.Acme.Models.Challenge> GetChallengeAsync(string challengeId)
  {
    if (_challenges.TryGetValue(challengeId, out var challenge))
      return Task.FromResult(challenge);
    throw new KeyNotFoundException($"Challenge {challengeId} not found");
  }

  public Task SetChallengeStatusAsync(string challengeId, ChallengeStatus status)
  {
    if (_challenges.TryGetValue(challengeId, out var challenge))
      challenge.Status = status.ToString().ToLower();
    return Task.CompletedTask;
  }

  public Task<string?> GetDnsRecordAsync(string validationDomain)
  {
    _dnsRecords.TryGetValue(validationDomain, out var value);
    return Task.FromResult(value);
  }

  public Task SetDnsRecordAsync(string validationDomain, string value)
  {
    _dnsRecords[validationDomain] = value;
    return Task.CompletedTask;
  }

  public Task<byte[]> GetPrivateKeyAsync(string accountKeyId)
  {
    if (_privateKeys.TryGetValue(accountKeyId, out var key))
      return Task.FromResult(key);
    throw new KeyNotFoundException($"Private key {accountKeyId} not found");
  }

  public Task SaveCertificateAsync(string domainName, byte[] certificate, byte[] privateKey)
  {
    _certificates[domainName] = (certificate, privateKey);
    return Task.CompletedTask;
  }

  public Task<Lakerfield.Acme.Models.CertificateBundle?> GetCertificateAsync(string domainName)
  {
    if (_certificates.TryGetValue(domainName, out var bundle))
    {
      return Task.FromResult<Lakerfield.Acme.Models.CertificateBundle?>(new Lakerfield.Acme.Models.CertificateBundle
      {
        Certificate = System.Text.Encoding.UTF8.GetString(bundle.cert),
        PrivateKey = System.Text.Encoding.UTF8.GetString(bundle.key),
        Domains = new List<string> { domainName },
        AcmeServerUrl = string.Empty,
      });
    }
    return Task.FromResult<Lakerfield.Acme.Models.CertificateBundle?>(null);
  }

  public Task RemoveCertificateAsync(string domainName)
  {
    _certificates.Remove(domainName);
    return Task.CompletedTask;
  }

  public Task<List<Lakerfield.Acme.Models.CertificateBundle>> GetAllCertificatesAsync()
  {
    var result = new List<Lakerfield.Acme.Models.CertificateBundle>();
    foreach (var (domain, bundle) in _certificates)
    {
      result.Add(new Lakerfield.Acme.Models.CertificateBundle
      {
        Certificate = System.Text.Encoding.UTF8.GetString(bundle.cert),
        PrivateKey = System.Text.Encoding.UTF8.GetString(bundle.key),
        Domains = new List<string> { domain },
        AcmeServerUrl = string.Empty,
      });
    }
    return Task.FromResult(result);
  }

  public void Dispose()
  {
    // Nothing to dispose for in-memory storage
  }
}
