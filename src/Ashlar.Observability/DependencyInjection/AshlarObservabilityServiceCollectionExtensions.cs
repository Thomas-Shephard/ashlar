// ReSharper disable CheckNamespace
#pragma warning disable IDE0130
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130

using Ashlar.Observability.SecurityEvents;

/// <summary>
/// Extension methods for registering Ashlar observability services.
/// </summary>
public static class AshlarObservabilityServiceCollectionExtensions
{
    /// <summary>
    /// Registers OpenTelemetry-compatible metrics for Ashlar security events.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional security event metrics configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarSecurityEventMetrics(
        this IServiceCollection services,
        Action<AshlarSecurityEventMetricsOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<AshlarSecurityEventMetricsOptions>();
        if (configure != null)
        {
            services.Configure(configure);
        }

        services.AddAshlarSecurityEventHandler<AshlarSecurityEventMetricsHandler>();

        return services;
    }
}
