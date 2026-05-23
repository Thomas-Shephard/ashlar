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
    /// Registers the Ashlar Redis-backed authentication rate limiter.
    /// </summary>
    /// <param name="services">The services value.</param>
    /// <param name="configuration">The Redis connection configuration.</param>
    /// <param name="configure">The configure value.</param>
    /// <returns>The operation result.</returns>
    public static IServiceCollection AddAshlarRedisRateLimiting(
        this IServiceCollection services,
        string configuration,
        Action<RedisAuthenticationRateLimiterOptions>? configure = null)
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
    /// Registers the Ashlar Redis-backed authentication rate limiter.
    /// </summary>
    /// <param name="services">The services value.</param>
    /// <param name="connection">The Redis connection multiplexer.</param>
    /// <param name="configure">The configure value.</param>
    /// <returns>The operation result.</returns>
    public static IServiceCollection AddAshlarRedisRateLimiting(
        this IServiceCollection services,
        IConnectionMultiplexer connection,
        Action<RedisAuthenticationRateLimiterOptions>? configure = null)
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
        services.Replace(ServiceDescriptor.Singleton(_ => new RedisAuthenticationRateLimiterConnection(connection, ownsConnection)));
        services.AddOptions<RedisAuthenticationRateLimiterOptions>()
            .Validate(RedisAuthenticationRateLimiterOptions.Validate, "Redis rate limiter options are invalid.");

        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddSingleton(TimeProvider.System);
        services.Replace(ServiceDescriptor.Singleton<IAuthenticationRateLimiter>(provider =>
            new RedisAuthenticationRateLimiter(
                provider.GetRequiredService<RedisAuthenticationRateLimiterConnection>(),
                provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<RedisAuthenticationRateLimiterOptions>>(),
                provider.GetRequiredService<TimeProvider>())));
        services.Replace(ServiceDescriptor.Singleton<IAuthenticationRateLimiterDiagnostics>(provider =>
            ActivatorUtilities.CreateInstance<RedisAuthenticationRateLimiterDiagnostics>(provider)));

        return services;
    }
}
