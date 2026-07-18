using Ashlar.Auditing;
using Ashlar.Identity.Passkeys;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Operational.Configuration;
using Ashlar.Passkeys;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

// ReSharper disable CheckNamespace
#pragma warning disable IDE0130
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130

public static partial class AshlarServiceCollectionExtensions
{
    /// <summary>Registers passkey orchestration and persistence services. Ceremony integrations call this method.</summary>
    /// <param name="services">The service collection to configure.</param>
    /// <returns>The same service collection.</returns>
    public static IServiceCollection AddAshlarPasskeyCore(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddOptions<PasskeyOptions>()
            .Validate(PasskeyOptions.Validate, "Passkey options are invalid.")
            .ValidateOnStart();
        services.AddAshlarMfaOrchestration();
        services.TryAddEnumerable(ServiceDescriptor.Scoped<IAuthenticationProvider, PasskeyAuthenticationProvider>());
        services.TryAddScoped<IPasskeyCredentialStore>(provider => new PasskeyCredentialStore(
            provider.GetRequiredAshlarProviderService<IUserRepository>(),
            provider.GetRequiredAshlarProviderService<ICredentialRepository>(),
            provider.GetRequiredService<IOptions<PasskeyOptions>>()));
        services.TryAddScoped<IPasskeyChallengeStore>(provider => new PasskeyChallengeStore(
            provider.GetRequiredAshlarProviderService<IPasskeyChallengeRepository>()));
        services.TryAddScoped<IPasskeyCredentialLookup>(provider => (IPasskeyCredentialLookup)provider.GetRequiredService<IPasskeyCredentialStore>());
        services.TryAddScoped(provider =>
        {
            var sink = provider.GetRequiredService<SecurityEventFanOutSink>();
            var transactions = provider.GetRequiredService<AshlarDurableTransactionProvider>();
            if (!sink.RequiresDurableTransaction || !ReferenceEquals(transactions, sink.TransactionProvider))
                throw new InvalidOperationException("Passkey mutations require durable audit using the same transaction provider.");
            if (!transactions.IncludesParticipant(provider.GetRequiredAshlarProviderService<IUserRepository>()))
                throw new InvalidOperationException("Passkey user persistence must be enlisted in the durable transaction composition.");
            if (!transactions.IncludesParticipant(provider.GetRequiredAshlarProviderService<ICredentialRepository>()))
                throw new InvalidOperationException("Passkey credential persistence must be enlisted in the durable transaction composition.");
            if (!transactions.IncludesParticipant(provider.GetRequiredAshlarProviderService<IPasskeyChallengeRepository>()))
                throw new InvalidOperationException("Passkey challenge persistence must be enlisted in the durable transaction composition.");
            if (!transactions.IncludesParticipant(provider.GetRequiredAshlarProviderService<IAuthenticationSessionRepository>()))
                throw new InvalidOperationException("Passkey session persistence must be enlisted in the durable transaction composition.");
            return new PasskeyServiceDependencies(
                provider.GetRequiredService<IOptions<PasskeyOptions>>(),
                provider.GetRequiredService<IAuthenticationOrchestrator>(),
                provider.GetRequiredService<IAuthenticationHandshakeService>(),
                provider.GetRequiredService<ISecureTokenHasher>(),
                provider.GetRequiredService<IAuthenticationRateLimiter>(),
                new PasskeyServiceInfrastructure(provider.GetService<TimeProvider>(), sink, transactions));
        });
        services.TryAddScoped<IPasskeyService, PasskeyService>();
        services.TryAddSingleton(provider => provider.GetRequiredService<IOptions<PasskeyOptions>>().Value);
        services.AddAshlarConfigurationValidation();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IAshlarConfigurationCheck, PasskeyConfigurationCheck>());
        return services;
    }
}
