namespace Ashlar.ProviderContracts.DependencyInjection;

using Ashlar.Identity.Abstractions.Transactions;
using Ashlar.Auditing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

/// <summary>Provider-authoring registration APIs. Applications should reference a persistence provider package instead.</summary>
public static class AshlarProviderServiceCollectionExtensions
{
    /// <summary>Determines whether a contract is registered in Ashlar's provider-owned infrastructure lane.</summary>
    /// <typeparam name="TService">The provider contract to inspect.</typeparam>
    /// <param name="provider">The service provider to inspect.</param>
    /// <returns><see langword="true" /> when the provider contract is registered; otherwise <see langword="false" />.</returns>
    public static bool IsAshlarProviderServiceRegistered<TService>(this IServiceProvider provider) where TService : class
    {
        ArgumentNullException.ThrowIfNull(provider);
        return provider.GetService<IServiceProviderIsService>()?.IsService(typeof(AshlarProviderService<TService>)) is true;
    }

    /// <summary>Resolves a private provider service for provider contract testing and provider-owned composition.</summary>
    /// <typeparam name="TService">The provider contract to resolve.</typeparam>
    /// <param name="provider">The provider-owned service provider scope.</param>
    /// <returns>The registered provider service.</returns>
    public static TService GetRequiredAshlarProviderService<TService>(this IServiceProvider provider) where TService : class
    {
        ArgumentNullException.ThrowIfNull(provider);
        return AshlarProviderServiceCollection.GetRequiredAshlarProviderService<TService>(provider);
    }

    /// <summary>Registers a provider-owned service factory in Ashlar's private infrastructure lane.</summary>
    /// <typeparam name="TService">The provider contract consumed by Ashlar.</typeparam>
    /// <param name="services">The provider package's service collection.</param>
    /// <param name="factory">The scoped provider service factory. Ashlar owns and disposes the returned value; do not return a disposable instance owned by another DI registration.</param>
    /// <returns>The same service collection.</returns>
    public static IServiceCollection AddAshlarProviderScoped<TService>(this IServiceCollection services, Func<IServiceProvider, TService> factory)
        where TService : class
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(factory);
        services.AddScoped(provider => new AshlarProviderService<TService>(factory(provider)));
        return services;
    }

    /// <summary>Replaces a provider-owned service factory in Ashlar's private infrastructure lane.</summary>
    /// <typeparam name="TService">The provider contract consumed by Ashlar.</typeparam>
    /// <param name="services">The provider package's service collection.</param>
    /// <param name="factory">The replacement scoped provider service factory. Ashlar owns and disposes the returned value; do not return a disposable instance owned by another DI registration.</param>
    /// <returns>The same service collection.</returns>
    public static IServiceCollection ReplaceAshlarProviderScoped<TService>(this IServiceCollection services, Func<IServiceProvider, TService> factory)
        where TService : class
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(factory);
        services.RemoveAll<AshlarProviderService<TService>>();
        return services.AddAshlarProviderScoped(factory);
    }

    /// <summary>Registers a provider-owned service in Ashlar's private infrastructure lane.</summary>
    /// <typeparam name="TService">The provider contract consumed by Ashlar.</typeparam>
    /// <typeparam name="TImplementation">The provider implementation.</typeparam>
    /// <param name="services">The provider package's service collection.</param>
    /// <returns>The same service collection.</returns>
    public static IServiceCollection TryAddAshlarProviderScoped<TService, TImplementation>(this IServiceCollection services)
        where TService : class
        where TImplementation : class, TService
    {
        ArgumentNullException.ThrowIfNull(services);
        return AshlarProviderServiceCollection.TryAddProviderScoped<TService, TImplementation>(services);
    }

    /// <summary>Creates Ashlar's durable transaction composition from a provider-owned transaction manager.</summary>
    /// <typeparam name="TProvider">The provider-owned transaction manager.</typeparam>
    /// <param name="services">The provider package's service collection.</param>
    /// <returns>The same service collection.</returns>
    public static IServiceCollection AddAshlarDurableTransactionProvider<TProvider>(this IServiceCollection services)
        where TProvider : class, IAshlarTransactionProvider
    {
        ArgumentNullException.ThrowIfNull(services);
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
