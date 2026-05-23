using Ashlar.AspNetCore.Diagnostics;
using Microsoft.Extensions.Diagnostics.HealthChecks;

#pragma warning disable IDE0130
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130

/// <summary>
/// Provides Ashlar health check registration helpers.
/// </summary>
public static class AshlarHealthChecksBuilderExtensions
{
    /// <summary>
    /// Adds all Ashlar health checks for diagnostics services registered in the service collection.
    /// </summary>
    /// <param name="builder">The health checks builder.</param>
    /// <param name="configureSchema">The optional schema health check options callback.</param>
    /// <param name="configureEmailOutbox">The optional email outbox health check options callback.</param>
    /// <param name="configureCleanup">The optional cleanup health check options callback.</param>
    /// <param name="configureRateLimiter">The optional rate limiter health check options callback.</param>
    /// <returns>The health checks builder.</returns>
    public static IHealthChecksBuilder AddAshlarHealthChecks(
        this IHealthChecksBuilder builder,
        Action<AshlarSchemaHealthCheckOptions>? configureSchema = null,
        Action<AshlarEmailOutboxHealthCheckOptions>? configureEmailOutbox = null,
        Action<AshlarCleanupHealthCheckOptions>? configureCleanup = null,
        Action<AshlarRateLimiterHealthCheckOptions>? configureRateLimiter = null)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.AddAshlarSchema(configureSchema);
        builder.AddAshlarEmailOutbox(configureEmailOutbox);
        builder.AddAshlarCleanup(configureCleanup);
        builder.AddAshlarRateLimiter(configureRateLimiter);

        return builder;
    }

    /// <summary>
    /// Adds the Ashlar schema health check.
    /// </summary>
    /// <param name="builder">The health checks builder.</param>
    /// <param name="configure">The optional schema health check options callback.</param>
    /// <param name="name">The health check registration name.</param>
    /// <param name="failureStatus">The optional failure status override.</param>
    /// <param name="tags">The optional health check tags.</param>
    /// <returns>The health checks builder.</returns>
    public static IHealthChecksBuilder AddAshlarSchema(
        this IHealthChecksBuilder builder,
        Action<AshlarSchemaHealthCheckOptions>? configure = null,
        string name = AshlarHealthCheckNames.Schema,
        HealthStatus? failureStatus = null,
        IEnumerable<string>? tags = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        if (configure is not null)
        {
            builder.Services.Configure(configure);
        }

        return builder.AddCheck<AshlarSchemaHealthCheck>(name, failureStatus, tags ?? []);
    }

    /// <summary>
    /// Adds the Ashlar email outbox health check.
    /// </summary>
    /// <param name="builder">The health checks builder.</param>
    /// <param name="configure">The optional email outbox health check options callback.</param>
    /// <param name="name">The health check registration name.</param>
    /// <param name="failureStatus">The optional failure status override.</param>
    /// <param name="tags">The optional health check tags.</param>
    /// <returns>The health checks builder.</returns>
    public static IHealthChecksBuilder AddAshlarEmailOutbox(
        this IHealthChecksBuilder builder,
        Action<AshlarEmailOutboxHealthCheckOptions>? configure = null,
        string name = AshlarHealthCheckNames.EmailOutbox,
        HealthStatus? failureStatus = null,
        IEnumerable<string>? tags = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        if (configure is not null)
        {
            builder.Services.Configure(configure);
        }

        return builder.AddCheck<AshlarEmailOutboxHealthCheck>(name, failureStatus, tags ?? []);
    }

    /// <summary>
    /// Adds the Ashlar cleanup health check.
    /// </summary>
    /// <param name="builder">The health checks builder.</param>
    /// <param name="configure">The optional cleanup health check options callback.</param>
    /// <param name="name">The health check registration name.</param>
    /// <param name="failureStatus">The optional failure status override.</param>
    /// <param name="tags">The optional health check tags.</param>
    /// <returns>The health checks builder.</returns>
    public static IHealthChecksBuilder AddAshlarCleanup(
        this IHealthChecksBuilder builder,
        Action<AshlarCleanupHealthCheckOptions>? configure = null,
        string name = AshlarHealthCheckNames.Cleanup,
        HealthStatus? failureStatus = null,
        IEnumerable<string>? tags = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        if (configure is not null)
        {
            builder.Services.Configure(configure);
        }

        return builder.AddCheck<AshlarCleanupHealthCheck>(name, failureStatus, tags ?? []);
    }

    /// <summary>
    /// Adds the Ashlar authentication rate limiter health check.
    /// </summary>
    /// <param name="builder">The health checks builder.</param>
    /// <param name="configure">The optional rate limiter health check options callback.</param>
    /// <param name="name">The health check registration name.</param>
    /// <param name="failureStatus">The optional failure status override.</param>
    /// <param name="tags">The optional health check tags.</param>
    /// <returns>The health checks builder.</returns>
    public static IHealthChecksBuilder AddAshlarRateLimiter(
        this IHealthChecksBuilder builder,
        Action<AshlarRateLimiterHealthCheckOptions>? configure = null,
        string name = AshlarHealthCheckNames.RateLimiter,
        HealthStatus? failureStatus = null,
        IEnumerable<string>? tags = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        if (configure is not null)
        {
            builder.Services.Configure(configure);
        }

        return builder.AddCheck<AshlarRateLimiterHealthCheck>(name, failureStatus, tags ?? []);
    }
}
