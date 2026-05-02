// ReSharper disable CheckNamespace

using Ashlar.Auditing;
using Ashlar.Identity;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Security.Encryption;
using Ashlar.Security.Hashing;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

#pragma warning disable IDE0130
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130

/// <summary>
/// Provides dependency injection registration helpers for Ashlar identity services.
/// </summary>
public static class AshlarServiceCollectionExtensions
{
    /// <summary>
    /// Registers Ashlar's core identity services.
    /// </summary>
    /// <remarks>
    /// This method intentionally does not register <see cref="IIdentityRepository"/> or
    /// <see cref="ISecretProtector"/>. Applications should provide those dependencies explicitly.
    /// </remarks>
    public static IServiceCollection AddAshlarIdentity(
        this IServiceCollection services,
        Action<IdentityServiceOptions>? configure = null,
        Action<AuthenticationSessionOptions>? configureSessions = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions();
        if (configure != null)
        {
            services.Configure(configure);
        }

        if (configureSessions != null)
        {
            services.Configure(configureSessions);
        }

        // IdentityService has multiple public constructors; use the full dependency graph explicitly.
        services.TryAdd(new ServiceDescriptor(
            typeof(IIdentityService),
            provider => new IdentityService(
                provider.GetRequiredService<IIdentityRepository>(),
                provider.GetRequiredService<IAuthenticationProviderRegistry>(),
                provider.GetRequiredService<ICredentialService>(),
                provider.GetRequiredService<IAuthenticationPipeline>(),
                provider.GetService<ISecurityEventSink>(),
                provider.GetService<TimeProvider>()),
            ServiceLifetime.Scoped));
        services.TryAddScoped<IAuthenticationPipeline, AuthenticationPipeline>();
        services.TryAddScoped<IAuthenticationProviderRegistry, AuthenticationProviderRegistry>();
        services.TryAddScoped<ICredentialService, CredentialService>();
        services.TryAddScoped<IAuthenticationSessionService, AuthenticationSessionService>();
        services.TryAddScoped<PasswordHasherSelector>();
        services.TryAddSingleton<ISessionTokenGenerator, RandomSessionTokenGenerator>();
        services.TryAddSingleton<ISessionTokenHasher, Sha256SessionTokenHasher>();
        services.TryAddSingleton<ISecurityEventSink, NullSecurityEventSink>();
        services.TryAddSingleton(provider => provider.GetRequiredService<IOptions<IdentityServiceOptions>>().Value);
        services.TryAddSingleton(provider => provider.GetRequiredService<IOptions<AuthenticationSessionOptions>>().Value);
        services.TryAddSingleton(TimeProvider.System);

        return services;
    }

    /// <summary>
    /// Registers an authentication provider implementation.
    /// </summary>
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

    /// <summary>
    /// Registers <see cref="DataProtectionSecretProtector"/> as Ashlar's secret protector.
    /// </summary>
    /// <remarks>
    /// The application must also register ASP.NET Core Data Protection services or another
    /// <see cref="Microsoft.AspNetCore.DataProtection.IDataProtectionProvider"/>.
    /// </remarks>
    public static IServiceCollection AddAshlarDataProtectionSecretProtector(
        this IServiceCollection services,
        ServiceLifetime lifetime = ServiceLifetime.Scoped)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarIdentity();
        services.TryAdd(new ServiceDescriptor(typeof(ISecretProtector), typeof(DataProtectionSecretProtector), lifetime));

        return services;
    }
}
