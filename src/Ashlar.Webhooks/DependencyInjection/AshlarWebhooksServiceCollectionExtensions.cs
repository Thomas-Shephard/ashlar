// ReSharper disable CheckNamespace
#pragma warning disable IDE0130
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130

using Ashlar.Webhooks.SecurityEvents;
using Microsoft.Extensions.DependencyInjection.Extensions;

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

        var httpClientBuilder = services.AddHttpClient(AshlarSecurityEventWebhookSender.HttpClientName)
            .ConfigurePrimaryHttpMessageHandler(CreateWebhookHttpMessageHandler);
        configureHttpClient?.Invoke(httpClientBuilder);
        services.AddOptions<AshlarSecurityEventWebhookOptions>()
            .Validate(AshlarSecurityEventWebhookOptions.Validate, "Ashlar security event webhook options are invalid.")
            .ValidateOnStart();
        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddSingleton<AshlarSecurityEventWebhookDeliveryFactory>();
        services.TryAddSingleton<IAshlarSecurityEventWebhookDestinationResolver, DnsAshlarSecurityEventWebhookDestinationResolver>();
        services.TryAddSingleton<AshlarSecurityEventWebhookDestinationValidator>();
        services.TryAddSingleton<IAshlarSecurityEventWebhookSender, AshlarSecurityEventWebhookSender>();
        services.TryAddSingleton<IAshlarSecurityEventWebhookDeliveryObserver>(_ => NoOpAshlarSecurityEventWebhookDeliveryObserver.Instance);
        services.AddAshlarSecurityEventHandler<AshlarSecurityEventWebhookHandler>();

        return services;
    }

    /// <summary>
    /// Registers durable outbox enqueue behavior for Ashlar security event webhooks.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional webhook configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarSecurityEventWebhookOutbox(
        this IServiceCollection services,
        Action<AshlarSecurityEventWebhookOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<AshlarSecurityEventWebhookOptions>()
            .Validate(AshlarSecurityEventWebhookOptions.Validate, "Ashlar security event webhook options are invalid.")
            .ValidateOnStart();
        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddSingleton<AshlarSecurityEventWebhookDeliveryFactory>();
        services.TryAddSingleton<IAshlarSecurityEventWebhookDestinationResolver, DnsAshlarSecurityEventWebhookDestinationResolver>();
        services.TryAddSingleton<AshlarSecurityEventWebhookDestinationValidator>();
        services.TryAddSingleton<IAshlarSecurityEventWebhookDeliveryObserver>(_ => NoOpAshlarSecurityEventWebhookDeliveryObserver.Instance);
        services.AddAshlarSecurityEventHandler<AshlarSecurityEventWebhookOutboxHandler>();

        return services;
    }

    private static HttpMessageHandler CreateWebhookHttpMessageHandler(IServiceProvider provider)
    {
        var destinationValidator = provider.GetRequiredService<AshlarSecurityEventWebhookDestinationValidator>();
        return AshlarSecurityEventWebhookHttpMessageHandlerFactory.Create(destinationValidator);
    }
}
