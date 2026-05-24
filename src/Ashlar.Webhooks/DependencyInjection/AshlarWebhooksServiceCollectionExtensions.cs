// ReSharper disable CheckNamespace
#pragma warning disable IDE0130
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130

using Ashlar.Webhooks.SecurityEvents;

/// <summary>
/// Extension methods for registering Ashlar webhook services.
/// </summary>
public static class AshlarWebhooksServiceCollectionExtensions
{
    /// <summary>
    /// Registers best-effort webhook delivery for Ashlar security events.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional webhook configuration.</param>
    /// <param name="configureHttpClient">Optional HTTP client builder configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarSecurityEventWebhooks(
        this IServiceCollection services,
        Action<AshlarSecurityEventWebhookOptions>? configure = null,
        Action<IHttpClientBuilder>? configureHttpClient = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        var httpClientBuilder = services.AddHttpClient(AshlarSecurityEventWebhookHandler.HttpClientName);
        configureHttpClient?.Invoke(httpClientBuilder);
        services.AddOptions<AshlarSecurityEventWebhookOptions>()
            .Validate(AshlarSecurityEventWebhookOptions.Validate, "Ashlar security event webhook options are invalid.")
            .ValidateOnStart();
        if (configure != null)
        {
            services.Configure(configure);
        }

        services.AddAshlarSecurityEventHandler<AshlarSecurityEventWebhookHandler>();

        return services;
    }
}
