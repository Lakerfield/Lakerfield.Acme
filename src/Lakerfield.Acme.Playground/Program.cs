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
// 2. Place an order for a wildcard domain
// 3. Provision the challenge (HTTP-01)
// 4. Provision the challenge (DNS-01)
// 5. Validate the challenge
// 6. Download the certificate
//
// Let's Encrypt staging server: https://acme-staging-v02.api.letsencrypt.org/directory
// Let's Encrypt production server: https://acme-v02.api.letsencrypt.org/directory
// ─────────────────────────────────────────────────────────────────────────────

var adminEmail = "admin@example.com";
string[] testDomain = ["wildcard.example.com", "*.wildcard.example.com"];
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

// Use Let's Encrypt staging for testing (no real certificates issued)
var acmeDirectoryUrl = WellKnownServers.LetsEncryptStaging;

using var client = new LakerfieldAcmeClient(acmeDirectoryUrl, new HttpClient());

Console.WriteLine($"ACME Server: {acmeDirectoryUrl}");
Console.WriteLine();

try
{
  // Step 1: Load the ACME directory
  Console.WriteLine("Step 1: Loading ACME directory...");
  await client.LoadDirectoryAsync();
  Console.WriteLine($"  newAccount: {client.Directory?.NewAccount}");
  Console.WriteLine($"  newOrder:   {client.Directory?.NewOrder}");
  Console.WriteLine($"  newNonce:   {client.Directory?.NewNonce}");
  if (client.Directory?.Meta?.Profiles is { Count: > 0 } profiles)
  {
    Console.WriteLine($"  profiles:");
    foreach (var (name, url) in profiles)
      Console.WriteLine($"    {name}: {url}");
  }
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

    account = await client.CreateAccountAsync(email: adminEmail, termsOfServiceAgreed: false); // set to true if you accept the tos of the provider
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
  Console.WriteLine($"Step 3: Creating order for {string.Join(", ", domain)}...");
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

    if (authz.Status == "valid")
    {
      Console.WriteLine($"  Authorization already valid, skipping challenges.");
      continue;
    }

    Challenge? http01Challenge = null;
    Challenge? dns01Challenge = null;
    Challenge? tlsAlpn01Challenge = null;
    foreach (var challenge in authz.Challenges)
    {
      Console.WriteLine($"    Challenge type: {challenge.Type}, status: {challenge.Status}");
      // Select the HTTP-01 challenge
      if (challenge.Type == "http-01")
        http01Challenge = challenge;

      // Select the DNS-01 challenge
      if (challenge.Type == "dns-01")
        dns01Challenge = challenge;

      // Select the TLS-ALPN-01 challenge
      if (challenge.Type == "tls-alpn-01")
        tlsAlpn01Challenge = challenge;
    }

    if (http01Challenge != null)
    {
      var token = http01Challenge.Token!;
      var keyAuthValue = client.GetHttpChallengeValue(token);
      var challengeUrl = $"http://{authz.Identifier}/.well-known/acme-challenge/{token}";

      Console.WriteLine();
      Console.WriteLine($"  HTTP-01 Challenge:");
      Console.WriteLine($"    Token: {token}");
      Console.WriteLine($"    Key Authorization: {keyAuthValue}");
      Console.WriteLine($"    URL: {challengeUrl}");
      Console.WriteLine();

      if (http01Challenge.Status == "valid")
      {
        Console.WriteLine($"  Challenge already valid, skipping validation.");
        continue;
      }

      Console.WriteLine($"  Token registered on the local web app:");
      Console.WriteLine($"    http://{authz.Identifier}/.well-known/acme-challenge/{token}");
      Console.WriteLine();

      // Register the token with the local web app so the ACME server can fetch it.
      tokenStore.AddToken(token, keyAuthValue);

      Console.WriteLine($"  Validating challenge...");
      await client.ValidateChallengeAsync(http01Challenge.Url!);
      Console.WriteLine($"  Waiting for challenge validation...");
      var validatedChallenge = await client.WaitForChallengeValidAsync(http01Challenge.Url!);
      Console.WriteLine($"  Challenge status: {validatedChallenge.Status}");

      tokenStore.RemoveToken(token);
      continue;
    }

    // DNS-01 example
    if (dns01Challenge != null)
    {
      var dnsValue = dns01Challenge.Token != null
        ? client.GetDnsChallengeValue(dns01Challenge.Token!)
        : "n/a";
      var dnsDomain = LakerfieldAcmeClient.GetDnsValidationDomain(authz.Identifier);
      var forwardLabel = LakerfieldAcmeClient.GetDnsValidationForwardLabel(authz.Identifier);
      var forwardedTxtRecord = $"{forwardLabel}.{acmeDomain}";
      Console.WriteLine($"  DNS-01 (as alternative):");
      Console.WriteLine($"    TXT record:         {dnsDomain}");

      if (dns01Challenge.Status == "valid")
      {
        Console.WriteLine($"  Challenge already valid, skipping validation.");
        continue;
      }

      Console.WriteLine($"    TXT record value:   {dnsValue}");
      Console.WriteLine($"    or CNAME forwarded: {forwardedTxtRecord}");

      // Register the token with the local dns so the ACME server can fetch it.
      dnsStore.SetTxtRecord(
        forwardedTxtRecord,
        dnsValue,
        ttl: 30,
        validFor: TimeSpan.FromMinutes(10));

      Console.WriteLine($"  Validating challenge...");
      await client.ValidateChallengeAsync(dns01Challenge.Url!);
      Console.WriteLine($"  Waiting for challenge validation...");
      var validatedChallenge = await client.WaitForChallengeValidAsync(dns01Challenge.Url!);
      Console.WriteLine($"  Challenge status: {validatedChallenge.Status}");

      dnsStore.RemoveRecord(forwardedTxtRecord);
      continue;
    }

    // TLS-ALPN-01 example
    if (tlsAlpn01Challenge != null)
    {
      // TODO: implement when needed
    }
  }

  Console.WriteLine();
  Console.WriteLine("Step 5: Requesting and downloading certificate...");

  Console.WriteLine("  Waiting for order to become 'ready'...");
  var readyOrder = await client.WaitForOrderReadyAsync(order.Url!);
  Console.WriteLine($"  Order status: {readyOrder.Status}");

  Console.WriteLine("  Finalizing order (submitting CSR)...");
  var (pendingOrder, certPrivateKey) = await client.FinalizeOrderAsync(readyOrder, domain);
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
  await Task.Delay(TimeSpan.FromMinutes(1));
  await webApp.StopAsync();
}
