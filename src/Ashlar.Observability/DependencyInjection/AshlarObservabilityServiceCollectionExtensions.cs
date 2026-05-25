// ReSharper disable CheckNamespace
#pragma warning disable IDE0130
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130

using Ashlar.Observability.SecurityEvents;
using Ashlar.Webhooks.SecurityEvents;
using Microsoft.Extensions.DependencyInjection.Extensions;

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

    /// <summary>
    /// Registers OpenTelemetry-compatible metrics for Ashlar security event webhook delivery attempts.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional security event webhook metrics configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarSecurityEventWebhookMetrics(
        this IServiceCollection services,
        Action<AshlarSecurityEventWebhookMetricsOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<AshlarSecurityEventWebhookMetricsOptions>();
        if (configure != null)
        {
            services.Configure(configure);
        }

        services.Replace(ServiceDescriptor.Singleton<IAshlarSecurityEventWebhookDeliveryObserver, AshlarSecurityEventWebhookMetricsObserver>());

        return services;
    }
}
