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
    /// <param name="services">The services value.</param>
    /// <param name="lifetime">The lifetime value.</param>
    /// <returns>The service collection.</returns>
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
    /// <param name="services">The services value.</param>
    /// <param name="implementationFactory">The implementation factory value.</param>
    /// <param name="lifetime">The lifetime value.</param>
    /// <returns>The service collection.</returns>
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
    /// <param name="services">The services value.</param>
    /// <param name="lifetime">The lifetime value.</param>
    /// <returns>The service collection.</returns>
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
    /// <param name="services">The services value.</param>
    /// <param name="implementationFactory">The implementation factory value.</param>
    /// <param name="lifetime">The lifetime value.</param>
    /// <returns>The service collection.</returns>
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
