using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using Lakerfield.Acme;
using Lakerfield.Acme.Models;
using Lakerfield.Acme.Playground;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

// ─── Playground voor Lakerfield.Acme ────────────────────────────────────────
//
// Dit voorbeeld laat de volledige ACME workflow zien:
// 1. Account aanmaken
// 2. Order plaatsen voor een domein
// 3. Challenge provisionen (HTTP-01)
// 4. Challenge valideren
// 5. Certificaat downloaden
//
// Let's Encrypt staging server: https://acme-staging-v02.api.letsencrypt.org/directory
// Let's Encrypt productie server: https://acme-v02.api.letsencrypt.org/directory
//
// OPMERKING: De minimale ASP.NET Core web app luistert op 0.0.0.0:80 voor HTTP-01 validatie.
// Op Linux/macOS vereist luisteren op poort 80 verhoogde rechten (bijv. sudo of CAP_NET_BIND_SERVICE).
// ─────────────────────────────────────────────────────────────────────────────

// ─── Minimale ASP.NET Core web app voor HTTP-01 challenge hosting ────────────
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAcmeHttp01Challenge();

var webApp = builder.Build();
webApp.Urls.Add("http://0.0.0.0:80");
webApp.UseAcmeHttp01Challenge();

var tokenStore = webApp.Services.GetRequiredService<AcmeChallengeTokenStore>();

await webApp.StartAsync();

Console.WriteLine("Lakerfield.Acme Playground");
Console.WriteLine("==========================");
Console.WriteLine();

// Gebruik de in-memory storage implementatie voor deze demo
var storage = new InMemoryAcmeStorage();

// Gebruik Let's Encrypt staging voor testing (geen echte certificaten)
var acmeServerUrl = "https://acme-staging-v02.api.letsencrypt.org/directory";

using var client = new LakerfieldAcmeClient(new HttpClient(), storage);
client.AcmeServerUrl = acmeServerUrl;

Console.WriteLine($"ACME Server: {acmeServerUrl}");
Console.WriteLine();

try
{
  // Stap 1: Laad de ACME directory
  Console.WriteLine("Stap 1: Laad ACME directory...");
  await client.LoadDirectoryAsync();
  Console.WriteLine($"  newAccount: {client.Directory?.NewAccount}");
  Console.WriteLine($"  newOrder:   {client.Directory?.NewOrder}");
  Console.WriteLine($"  newNonce:   {client.Directory?.NewNonce}");
  Console.WriteLine();

  // Stap 2: Laad bestaand account of maak een nieuw account aan
  var keyPath = Path.Combine(Path.GetTempPath(), "acme-account-key.der");
  var accountUrlPath = Path.Combine(Path.GetTempPath(), "acme-account-url.txt");

  Account account;
  if (File.Exists(keyPath) && File.Exists(accountUrlPath))
  {
    Console.WriteLine("Stap 2: Bestaand account laden...");
    var savedKey = await File.ReadAllBytesAsync(keyPath);
    var savedAccountUrl = await File.ReadAllTextAsync(accountUrlPath);
    Console.WriteLine($"  Private key geladen: {keyPath}");
    Console.WriteLine($"  Account URL geladen: {savedAccountUrl}");

    account = await client.LoadAccountAsync(savedAccountUrl, savedKey);
    Console.WriteLine($"  Account geladen: {account.Url}");
    Console.WriteLine($"  Account status: {account.Status}");
  }
  else
  {
    Console.WriteLine("Stap 2: Nieuw account aanmaken...");
    var privateKey = client.GenerateAccountKey();
    Console.WriteLine($"  EC P-256 private key gegenereerd ({privateKey.Length} bytes)");

    account = await client.CreateAccountAsync(email: "admin@example.com");
    Console.WriteLine($"  Account aangemaakt: {account.Url}");
    Console.WriteLine($"  Account status: {account.Status}");

    // Sla de private key en account URL op voor later gebruik
    await File.WriteAllBytesAsync(keyPath, privateKey);
    await File.WriteAllTextAsync(accountUrlPath, account.Url);
    Console.WriteLine($"  Private key opgeslagen: {keyPath}");
    Console.WriteLine($"  Account URL opgeslagen: {accountUrlPath}");
  }

  Console.WriteLine();

  // Stap 3: Maak een order aan voor een domein
  var domain = "example.com";
  Console.WriteLine($"Stap 3: Order aanmaken voor {domain}...");
  var order = await client.CreateOrderAsync(domain);
  Console.WriteLine($"  Order URL: {order.Url}");
  Console.WriteLine($"  Order status: {order.Status}");
  Console.WriteLine($"  Authorizations: {order.Authorizations.Count}");
  Console.WriteLine();

  // Stap 4: Verwerk elke authorization
  Console.WriteLine("Stap 4: Authorizations verwerken...");
  foreach (var authzUrl in order.Authorizations)
  {
    Console.WriteLine($"  Authorization: {authzUrl}");
    var authz = await client.GetAuthorizationAsync(authzUrl);
    Console.WriteLine($"  Domein: {authz.Identifier}");
    Console.WriteLine($"  Status: {authz.Status}");

    // Kies de HTTP-01 challenge
    Challenge? httpChallenge = null;
    foreach (var challenge in authz.Challenges)
    {
      Console.WriteLine($"    Challenge type: {challenge.Type}, status: {challenge.Status}");
      if (challenge.Type == "http-01")
        httpChallenge = challenge;
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
      Console.WriteLine($"  Token geregistreerd op de lokale web app:");
      Console.WriteLine($"    http://{authz.Identifier}/.well-known/acme-challenge/{token}");
      Console.WriteLine();

      // Registreer de token in de lokale web app zodat de ACME server hem kan ophalen.
      tokenStore.AddToken(token, keyAuthValue);

      Console.WriteLine($"  Challenge valideren...");
      await client.ValidateChallengeAsync(httpChallenge.Url!);
      Console.WriteLine($"  Wachten op challenge validatie...");
      var validatedChallenge = await client.WaitForChallengeValidAsync(httpChallenge.Url!);
      Console.WriteLine($"  Challenge status: {validatedChallenge.Status}");

      tokenStore.RemoveToken(token);
    }

    // DNS-01 voorbeeld
    var dnsValue = authz.Challenges.Count > 0 && authz.Challenges[0].Token != null
      ? client.GetDnsChallengeValue(authz.Challenges[0].Token!)
      : "n/a";
    var dnsDomain = LakerfieldAcmeClient.GetDnsValidationDomain(authz.Identifier);
    Console.WriteLine($"  DNS-01 (als alternatief):");
    Console.WriteLine($"    TXT record domein: {dnsDomain}");
    Console.WriteLine($"    TXT record waarde: {dnsValue}");
  }

  Console.WriteLine();
  Console.WriteLine("Stap 5: Certificaat aanvragen en downloaden...");

  Console.WriteLine("  Wachten tot order 'ready' is...");
  var readyOrder = await client.WaitForOrderReadyAsync(order.Url!);
  Console.WriteLine($"  Order status: {readyOrder.Status}");

  Console.WriteLine("  Order finaliseren (CSR indienen)...");
  var (pendingOrder, certPrivateKey) = await client.FinalizeOrderAsync(readyOrder, new[] { domain });
  Console.WriteLine($"  Order status na finaliseren: {pendingOrder.Status}");

  Console.WriteLine("  Wachten tot order 'valid' is...");
  var validOrder = await client.WaitForOrderValidAsync(pendingOrder.Url!);
  Console.WriteLine($"  Order status: {validOrder.Status}");

  Console.WriteLine("  Certificaat downloaden...");
  var pem = await client.DownloadCertificateAsync(validOrder);
  Console.WriteLine();
  Console.WriteLine("─── PEM Certificaat ────────────────────────────────────────────────────────");
  Console.WriteLine(pem);
  Console.WriteLine("────────────────────────────────────────────────────────────────────────────");
  Console.WriteLine();
  Console.WriteLine("Demo succesvol afgerond!");
}
catch (AcmeException ex)
{
  Console.ForegroundColor = ConsoleColor.Red;
  Console.WriteLine($"ACME Fout: {ex.Message}");
  Console.ResetColor();
}
catch (Exception ex)
{
  Console.ForegroundColor = ConsoleColor.Red;
  Console.WriteLine($"Fout: {ex.GetType().Name}: {ex.Message}");
  Console.ResetColor();
}
finally
{
  await webApp.StopAsync();
}

// ─── In-Memory Storage implementatie ────────────────────────────────────────

/// <summary>
/// Eenvoudige in-memory implementatie van IAcmeStorage voor demo doeleinden.
/// In productie gebruik je MongoDB, disk, of een andere persistente storage.
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
