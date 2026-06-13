// ReSharper disable CheckNamespace
#pragma warning disable IDE0130
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130

using Ashlar.Security.Hashing;
using Microsoft.Extensions.DependencyInjection.Extensions;

public static partial class AshlarServiceCollectionExtensions
{
    /// <summary>
    /// Registers an authentication provider implementation.
    /// </summary>
    /// <typeparam name="TProvider">The authentication provider implementation type.</typeparam>
    /// <param name="services">Service collection to add the provider registration to.</param>
    /// <param name="lifetime">Service lifetime for the provider implementation.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAuthenticationProvider<TProvider>(
        this IServiceCollection services,
        ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TProvider : class, IAuthenticationProvider
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarIdentity();
        services.TryAddEnumerable(ServiceDescriptor.Describe(typeof(IAuthenticationProvider), typeof(TProvider), lifetime));

        return services;
    }

    /// <summary>
    /// Registers an authentication provider factory.
    /// </summary>
    /// <param name="services">Service collection to add the provider registration to.</param>
    /// <param name="implementationFactory">Factory that creates the provider instance.</param>
    /// <param name="lifetime">Service lifetime for provider instances produced by the factory.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    /// <remarks>
    /// Use this overload when multiple named providers are backed by the same implementation type.
    /// </remarks>
    public static IServiceCollection AddAuthenticationProvider(
        this IServiceCollection services,
        Func<IServiceProvider, IAuthenticationProvider> implementationFactory,
        ServiceLifetime lifetime = ServiceLifetime.Scoped)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(implementationFactory);

        services.AddAshlarIdentity();
        services.Add(new ServiceDescriptor(typeof(IAuthenticationProvider), implementationFactory, lifetime));

        return services;
    }

    /// <summary>
    /// Registers a password hasher implementation.
    /// </summary>
    /// <typeparam name="THasher">The password hasher implementation type.</typeparam>
    /// <param name="services">Service collection to add the password hasher registration to.</param>
    /// <param name="lifetime">Service lifetime for the password hasher implementation.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddPasswordHasher<THasher>(
        this IServiceCollection services,
        ServiceLifetime lifetime = ServiceLifetime.Singleton)
        where THasher : class, IPasswordHasher
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarIdentity();
        services.TryAddEnumerable(ServiceDescriptor.Describe(typeof(IPasswordHasher), typeof(THasher), lifetime));

        return services;
    }

    /// <summary>
    /// Registers a password hasher factory.
    /// </summary>
    /// <param name="services">Service collection to add the password hasher registration to.</param>
    /// <param name="implementationFactory">Factory that creates the password hasher instance.</param>
    /// <param name="lifetime">Service lifetime for password hasher instances produced by the factory.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddPasswordHasher(
        this IServiceCollection services,
        Func<IServiceProvider, IPasswordHasher> implementationFactory,
        ServiceLifetime lifetime = ServiceLifetime.Singleton)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(implementationFactory);

        services.AddAshlarIdentity();
        services.Add(new ServiceDescriptor(typeof(IPasswordHasher), implementationFactory, lifetime));

        return services;
    }
}
