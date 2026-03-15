using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Lakerfield.Acme;

public static class AcmeDnsServiceCollectionExtensions
{
  public static IServiceCollection AddAcmeDnsServer(
    this IServiceCollection services,
    Action<AcmeDnsServerOptions> configure)
  {
    services.Configure(configure);

    services.TryAddSingleton<IAcmeDnsChallengeStore, AcmeDnsInMemoryChallengeStore>();
    services.AddHostedService<AcmeDnsHostedService>();

    return services;
  }
}
