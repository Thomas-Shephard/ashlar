using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Operational.Diagnostics;
using Microsoft.Extensions.DependencyInjection.Extensions;
using StackExchange.Redis;

// ReSharper disable CheckNamespace
#pragma warning disable IDE0130
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130

/// <summary>
/// Provides Ashlar Redis service collection extensions.
/// </summary>
public static class AshlarRedisServiceCollectionExtensions
{
    /// <summary>
    /// Registers the Ashlar Redis-backed authentication rate limiter with default options.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configuration">Redis connection configuration used to create a managed multiplexer.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarRedisRateLimiting(
        this IServiceCollection services,
        string configuration) => services.AddAshlarRedisRateLimiting(configuration, null);

    /// <summary>
    /// Registers the Ashlar Redis-backed authentication rate limiter, diagnostics, and safe administration operations.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configuration">Redis connection configuration used to create a managed multiplexer.</param>
    /// <param name="configure">Optional rate limiter configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarRedisRateLimiting(
        this IServiceCollection services,
        string configuration,
        Action<RedisAuthenticationRateLimiterOptions>? configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(configuration);

        var connection = new Lazy<Task<IConnectionMultiplexer>>(async () =>
        {
            var options = ConfigurationOptions.Parse(configuration);
            options.AbortOnConnectFail = false;
            return await ConnectionMultiplexer.ConnectAsync(options);
        });
        return services.AddAshlarRedisRateLimiting(connection, true, configure);
    }

    /// <summary>
    /// Registers the Ashlar Redis-backed authentication rate limiter with default options.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="connection">Redis connection multiplexer owned by the host application.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarRedisRateLimiting(
        this IServiceCollection services,
        IConnectionMultiplexer connection) => services.AddAshlarRedisRateLimiting(connection, null);

    /// <summary>
    /// Registers the Ashlar Redis-backed authentication rate limiter, diagnostics, and safe administration operations.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="connection">Redis connection multiplexer owned by the host application.</param>
    /// <param name="configure">Optional rate limiter configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarRedisRateLimiting(
        this IServiceCollection services,
        IConnectionMultiplexer connection,
        Action<RedisAuthenticationRateLimiterOptions>? configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(connection);

        return services.AddAshlarRedisRateLimiting(new Lazy<Task<IConnectionMultiplexer>>(() => Task.FromResult(connection)), false, configure);
    }

    private static IServiceCollection AddAshlarRedisRateLimiting(
        this IServiceCollection services,
        Lazy<Task<IConnectionMultiplexer>> connection,
        bool ownsConnection,
        Action<RedisAuthenticationRateLimiterOptions>? configure)
    {
        services.AddAshlarAuthenticationRateLimitProviderMarker("Redis");
        services.Replace(ServiceDescriptor.Singleton(_ => new RedisAuthenticationRateLimiterConnection(connection, ownsConnection)));
        services.AddOptions<RedisAuthenticationRateLimiterOptions>()
            .Validate(RedisAuthenticationRateLimiterOptions.Validate, "Redis rate limiter options are invalid.")
            .ValidateOnStart();

        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddSingleton(TimeProvider.System);
        services.Replace(ServiceDescriptor.Singleton<IAuthenticationRateLimiter>(provider =>
            new RedisAuthenticationRateLimiter(
                provider.GetRequiredService<RedisAuthenticationRateLimiterConnection>(),
                provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<RedisAuthenticationRateLimiterOptions>>())));
        services.Replace(ServiceDescriptor.Singleton<IAuthenticationRateLimiterDiagnostics>(provider =>
            ActivatorUtilities.CreateInstance<RedisAuthenticationRateLimiterDiagnostics>(provider)));
        services.AddAshlarAuthenticationRateLimitAdministrationReader(provider =>
            new RedisAuthenticationRateLimitAdministrationRepository(
                provider.GetRequiredService<RedisAuthenticationRateLimiterConnection>(),
                provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<RedisAuthenticationRateLimiterOptions>>()));

        return services;
    }
}
