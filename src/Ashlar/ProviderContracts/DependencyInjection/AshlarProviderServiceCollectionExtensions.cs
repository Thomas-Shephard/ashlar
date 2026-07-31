namespace Ashlar.ProviderContracts.DependencyInjection;

using Ashlar.Auditing;
using Ashlar.Identity.Abstractions.Repositories;
using Ashlar.Identity.Abstractions.Transactions;
using Ashlar.Operational;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

/// <summary>Provider-authoring registration APIs. Applications should reference a persistence provider package instead.</summary>
public static class AshlarProviderServiceCollectionExtensions
{
    /// <summary>Claims Ashlar's durable persistence bundle for one provider family.</summary>
    /// <typeparam name="TProvider">The transaction provider type that uniquely owns the bundle.</typeparam>
    /// <param name="services">The provider package's service collection.</param>
    /// <param name="family">A stable provider-family name.</param>
    /// <returns>The same service collection.</returns>
    public static IServiceCollection AddAshlarDurableProviderBundle<TProvider>(this IServiceCollection services, string family)
        where TProvider : class, IAshlarTransactionProvider
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(family);
        return AshlarProviderServiceCollection.AddDurableProviderBundle(services, typeof(TProvider), family);
    }

    /// <summary>Determines whether a contract is registered in Ashlar's provider-owned infrastructure lane.</summary>
    /// <typeparam name="TService">The provider contract to inspect.</typeparam>
    /// <param name="provider">The service provider to inspect.</param>
    /// <returns><see langword="true" /> when the provider contract is registered; otherwise <see langword="false" />.</returns>
    public static bool IsAshlarProviderServiceRegistered<TService>(this IServiceProvider provider) where TService : class
    {
        ArgumentNullException.ThrowIfNull(provider);
        return provider.GetService<IServiceProviderIsService>()?.IsService(typeof(AshlarProviderService<TService>)) is true;
    }

    /// <summary>Registers a provider-owned service factory in Ashlar's private infrastructure lane.</summary>
    /// <typeparam name="TProvider">The transaction provider type that owns the service.</typeparam>
    /// <typeparam name="TService">The provider contract consumed by Ashlar.</typeparam>
    /// <param name="services">The provider package's service collection.</param>
    /// <param name="family">The durable provider family name used in conflict diagnostics.</param>
    /// <param name="factory">The scoped provider service factory. Ashlar owns and disposes the returned value; do not return a disposable instance owned by another DI registration.</param>
    /// <returns>The same service collection.</returns>
    public static IServiceCollection AddAshlarProviderScoped<TProvider, TService>(
        this IServiceCollection services,
        string family,
        Func<IServiceProvider, TService> factory)
        where TProvider : class, IAshlarTransactionProvider
        where TService : class
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(factory);
        services.AddAshlarDurableProviderBundle<TProvider>(family);
        services.AddScoped(provider => new AshlarProviderService<TService>(factory(provider)));
        return services;
    }

    /// <summary>Replaces a provider-owned service factory in Ashlar's private infrastructure lane.</summary>
    /// <typeparam name="TProvider">The transaction provider type that owns the service.</typeparam>
    /// <typeparam name="TService">The provider contract consumed by Ashlar.</typeparam>
    /// <param name="services">The provider package's service collection.</param>
    /// <param name="family">The durable provider family name used in conflict diagnostics.</param>
    /// <param name="factory">The replacement scoped provider service factory. Ashlar owns and disposes the returned value; do not return a disposable instance owned by another DI registration.</param>
    /// <returns>The same service collection.</returns>
    public static IServiceCollection ReplaceAshlarProviderScoped<TProvider, TService>(
        this IServiceCollection services,
        string family,
        Func<IServiceProvider, TService> factory)
        where TProvider : class, IAshlarTransactionProvider
        where TService : class
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(factory);
        services.AddAshlarDurableProviderBundle<TProvider>(family);
        services.RemoveAll<AshlarProviderService<TService>>();
        services.AddScoped(provider => new AshlarProviderService<TService>(factory(provider)));
        return services;
    }

    /// <summary>Replaces and publishes a provider-owned operational administration implementation.</summary>
    /// <typeparam name="TProvider">The transaction provider type that owns the service.</typeparam>
    /// <typeparam name="TService">The application-facing operational administration contract.</typeparam>
    /// <typeparam name="TImplementation">The provider implementation.</typeparam>
    /// <param name="services">The provider package's service collection.</param>
    /// <param name="family">The durable provider family name used in conflict diagnostics.</param>
    /// <param name="kind">The operational boundary configuration.</param>
    /// <returns>The same service collection.</returns>
    public static IServiceCollection ReplaceAshlarOperationalAdministrationScoped<TProvider, TService, TImplementation>(
        this IServiceCollection services,
        string family,
        AshlarOperationalAdministrationKind kind)
        where TProvider : class, IAshlarTransactionProvider
        where TService : class
        where TImplementation : class, TService
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddAshlarDurableProviderBundle<TProvider>(family);
        services.RemoveAll<TService>();
        services.AddScoped<TService>(provider => ActivatorUtilities.CreateInstance<TImplementation>(
            provider, CreateOperationalAdministrationContext(provider, kind)));
        return services;
    }

    private static AshlarOperationalAdministrationContext CreateOperationalAdministrationContext(
        IServiceProvider provider,
        AshlarOperationalAdministrationKind kind)
    {
        var sessions = AshlarProviderServiceCollection.GetRequiredAshlarProviderService<IAuthenticationSessionRepository>(provider);
        var auditSink = AshlarProviderServiceCollection.GetRequiredAshlarProviderService<IPersistentSecurityEventSink>(provider);
        var authorizer = provider.GetRequiredService<IAccountSecurityOperationAuthorizer>();
        var timeProvider = provider.GetRequiredService<TimeProvider>();
        var (readEventType, mutationEventType) = kind switch
        {
            AshlarOperationalAdministrationKind.EmailOutbox =>
                (AshlarSecurityEventTypes.EmailOutboxAdministration, AshlarSecurityEventTypes.EmailOutboxAdministration),
            AshlarOperationalAdministrationKind.SecurityEventWebhookOutbox =>
                (AshlarSecurityEventTypes.SecurityEventWebhookOutboxBrowse, AshlarSecurityEventTypes.SecurityEventWebhookOutboxOperation),
            _ => throw new ArgumentOutOfRangeException(nameof(kind))
        };
        return new(
            new(sessions, authorizer, auditSink, timeProvider, eventType: readEventType),
            new(sessions, authorizer, auditSink, timeProvider, IAccountSecurityAdministrationService.ProofPurpose,
                mutationEventType));
    }

    /// <summary>Registers a provider-owned service in Ashlar's private infrastructure lane.</summary>
    /// <typeparam name="TProvider">The transaction provider type that owns the service.</typeparam>
    /// <typeparam name="TService">The provider contract consumed by Ashlar.</typeparam>
    /// <typeparam name="TImplementation">The provider implementation.</typeparam>
    /// <param name="services">The provider package's service collection.</param>
    /// <param name="family">The durable provider family name used in conflict diagnostics.</param>
    /// <returns>The same service collection.</returns>
    public static IServiceCollection TryAddAshlarProviderScoped<TProvider, TService, TImplementation>(
        this IServiceCollection services,
        string family)
        where TProvider : class, IAshlarTransactionProvider
        where TService : class
        where TImplementation : class, TService
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddAshlarDurableProviderBundle<TProvider>(family);
        return AshlarProviderServiceCollection.TryAddProviderScoped<TService, TImplementation>(services);
    }

    /// <summary>Creates Ashlar's durable transaction composition from a provider-owned transaction manager.</summary>
    /// <typeparam name="TProvider">The provider-owned transaction manager.</typeparam>
    /// <param name="services">The provider package's service collection.</param>
    /// <param name="family">The durable provider family name used in conflict diagnostics.</param>
    /// <returns>The same service collection.</returns>
    public static IServiceCollection AddAshlarDurableTransactionProvider<TProvider>(this IServiceCollection services, string family)
        where TProvider : class, IAshlarTransactionProvider
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddAshlarDurableProviderBundle<TProvider>(family);
        return AshlarServiceCollectionExtensions.AddProviderDurableTransactionProvider<TProvider>(services);
    }

    /// <summary>Creates Ashlar's durable transaction composition from an ordinary-DI-owned transaction manager without transferring disposal ownership.</summary>
    /// <typeparam name="TProvider">The provider-owned transaction manager.</typeparam>
    /// <param name="services">The provider package's service collection.</param>
    /// <param name="family">The durable provider family name used in conflict diagnostics.</param>
    /// <param name="factory">The scoped transaction manager factory.</param>
    /// <returns>The same service collection.</returns>
    public static IServiceCollection AddAshlarDurableTransactionProvider<TProvider>(
        this IServiceCollection services,
        string family,
        Func<IServiceProvider, TProvider> factory)
        where TProvider : class, IAshlarTransactionProvider
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(factory);
        services.AddAshlarDurableProviderBundle<TProvider>(family);
        services.TryAddScoped(provider => new AshlarProviderService<TProvider>(factory(provider), ownsValue: false));
        return AshlarServiceCollectionExtensions.AddProviderDurableTransactionProvider<TProvider>(services);
    }

    /// <summary>Declares a provider-owned service as enlisted in the provider transaction.</summary>
    /// <typeparam name="TParticipant">The provider contract sharing the transaction.</typeparam>
    /// <param name="services">The provider package's service collection.</param>
    /// <returns>The same service collection.</returns>
    public static IServiceCollection AddAshlarDurableTransactionParticipant<TParticipant>(this IServiceCollection services)
        where TParticipant : class
    {
        ArgumentNullException.ThrowIfNull(services);
        return AshlarServiceCollectionExtensions.AddProviderDurableTransactionParticipant<TParticipant>(services);
    }

    /// <summary>Declares the core identity persistence services as provider transaction participants.</summary>
    /// <param name="services">The provider package's service collection.</param>
    /// <returns>The same service collection.</returns>
    public static IServiceCollection AddAshlarIdentityDurableTransactionParticipants(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        return AshlarServiceCollectionExtensions.AddProviderIdentityDurableTransactionParticipants(services);
    }

    /// <summary>Registers a provider-owned, transaction-bound security event continuation.</summary>
    /// <typeparam name="THandler">The durable provider handler type.</typeparam>
    /// <param name="services">The provider package's service collection.</param>
    /// <returns>The same service collection.</returns>
    public static IServiceCollection AddAshlarDurableSecurityEventFanOutHandler<THandler>(this IServiceCollection services)
        where THandler : class, IDurableSecurityEventFanOutHandler
    {
        ArgumentNullException.ThrowIfNull(services);
        return AshlarServiceCollectionExtensions.AddProviderDurableSecurityEventFanOutHandler<THandler>(services);
    }
}
