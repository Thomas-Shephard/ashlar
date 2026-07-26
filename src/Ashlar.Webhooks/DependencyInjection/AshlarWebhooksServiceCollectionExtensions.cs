// ReSharper disable CheckNamespace
#pragma warning disable IDE0130
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130

using Ashlar.Webhooks.SecurityEvents;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

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
    /// <param name="configureHttpClient">Optional <see cref="HttpClient" /> configuration. The primary handler is Ashlar-owned.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarSecurityEventWebhooks(
        this IServiceCollection services,
        Action<AshlarSecurityEventWebhookOptions>? configure = null,
        Action<HttpClient>? configureHttpClient = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        var httpClientBuilder = services.AddHttpClient(AshlarSecurityEventWebhookSender.HttpClientName)
            .ConfigurePrimaryHttpMessageHandler(CreateWebhookHttpMessageHandler);
        if (configureHttpClient != null)
        {
            httpClientBuilder.ConfigureHttpClient(configureHttpClient);
        }
        services.AddOptions<AshlarSecurityEventWebhookOptions>()
            .Validate(AshlarSecurityEventWebhookOptions.Validate, "Ashlar security event webhook options are invalid.")
            .ValidateOnStart();
        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<AshlarSecurityEventWebhookDeliveryFactory>();
        services.TryAddSingleton<IAshlarSecurityEventWebhookDestinationResolver, DnsAshlarSecurityEventWebhookDestinationResolver>();
        services.TryAddSingleton<AshlarSecurityEventWebhookDestinationValidator>();
        services.TryAddSingleton<IAshlarSecurityEventWebhookSender, AshlarSecurityEventWebhookSender>();
        services.TryAddScoped<IAshlarSecurityEventWebhookEndpointTester, AshlarSecurityEventWebhookEndpointTester>();
        services.TryAddSingleton<IAshlarSecurityEventWebhookDeliveryObserver>(NoOpAshlarSecurityEventWebhookDeliveryObserver.Instance);
        services.AddAshlarSecurityEventHandler<AshlarSecurityEventWebhookHandler>();

        return services;
    }

    /// <summary>
    /// Registers transaction-bound outbox enqueue behavior for Ashlar security event webhooks.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional webhook configuration.</param>
    /// <param name="configureHttpClient">Optional safe <see cref="HttpClient" /> configuration. Ashlar owns the primary handler.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarSecurityEventWebhookOutbox(
        this IServiceCollection services,
        Action<AshlarSecurityEventWebhookOptions>? configure = null,
        Action<HttpClient>? configureHttpClient = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<AshlarSecurityEventWebhookOptions>()
            .Validate(AshlarSecurityEventWebhookOptions.Validate, "Ashlar security event webhook options are invalid.")
            .ValidateOnStart();
        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<AshlarSecurityEventWebhookDeliveryFactory>();
        services.TryAddSingleton<IAshlarSecurityEventWebhookDestinationResolver, DnsAshlarSecurityEventWebhookDestinationResolver>();
        services.TryAddSingleton<AshlarSecurityEventWebhookDestinationValidator>();
        services.AddOptions<AshlarSecurityEventWebhookTransportOptions>();
        if (configureHttpClient != null)
        {
            services.Configure<AshlarSecurityEventWebhookTransportOptions>(options => options.Configurations.Add(configureHttpClient));
        }
        services.TryAddSingleton(provider => new AshlarSecurityEventWebhookTransport(
            provider.GetRequiredService<AshlarSecurityEventWebhookDestinationValidator>(),
            provider.GetRequiredService<IOptions<AshlarSecurityEventWebhookTransportOptions>>().Value.Configurations));
        services.TryAddSingleton<IAshlarSecurityEventWebhookDeliveryObserver>(NoOpAshlarSecurityEventWebhookDeliveryObserver.Instance);

        return services;
    }

    /// <summary>
    /// Registers a singleton observer for Ashlar security event webhook delivery attempts.
    /// </summary>
    /// <typeparam name="TObserver">The observer type to register.</typeparam>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarSecurityEventWebhookDeliveryObserver<TObserver>(this IServiceCollection services)
        where TObserver : class, IAshlarSecurityEventWebhookDeliveryObserver
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton<TObserver>();
        EnsureWebhookDeliveryObserverComposite(services);
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IAshlarSecurityEventWebhookDeliveryObserverContribution, AshlarSecurityEventWebhookDeliveryObserverContribution<TObserver>>());

        return services;
    }

    private static HttpMessageHandler CreateWebhookHttpMessageHandler(IServiceProvider provider)
    {
        var destinationValidator = provider.GetRequiredService<AshlarSecurityEventWebhookDestinationValidator>();
        return AshlarSecurityEventWebhookHttpMessageHandlerFactory.Create(destinationValidator);
    }

    private static void PreserveExistingWebhookDeliveryObservers(IServiceCollection services)
    {
        for (var index = services.Count - 1; index >= 0; index--)
        {
            var descriptor = services[index];
            if (descriptor.ServiceType != typeof(IAshlarSecurityEventWebhookDeliveryObserver))
            {
                continue;
            }

            services.RemoveAt(index);
            if (ReferenceEquals(descriptor.ImplementationInstance, NoOpAshlarSecurityEventWebhookDeliveryObserver.Instance))
            {
                continue;
            }

            services.Insert(index, CreateWebhookDeliveryObserverContributionDescriptor(descriptor));
        }
    }

    private static ServiceDescriptor CreateWebhookDeliveryObserverContributionDescriptor(ServiceDescriptor descriptor)
    {
        return ServiceDescriptor.Describe(
            typeof(IAshlarSecurityEventWebhookDeliveryObserverContribution),
            provider => new AshlarSecurityEventWebhookDeliveryObserverContribution<IAshlarSecurityEventWebhookDeliveryObserver>(
                CreateWebhookDeliveryObserver(provider, descriptor)),
            ServiceLifetime.Singleton);
    }

    private static IAshlarSecurityEventWebhookDeliveryObserver CreateWebhookDeliveryObserver(IServiceProvider provider, ServiceDescriptor descriptor)
    {
        if (descriptor.ImplementationInstance is IAshlarSecurityEventWebhookDeliveryObserver instance)
        {
            return instance;
        }

        if (descriptor.ImplementationFactory != null)
        {
            return (IAshlarSecurityEventWebhookDeliveryObserver)descriptor.ImplementationFactory(provider);
        }

        return (IAshlarSecurityEventWebhookDeliveryObserver)ActivatorUtilities.GetServiceOrCreateInstance(provider, descriptor.ImplementationType!);
    }

    private static void EnsureWebhookDeliveryObserverComposite(IServiceCollection services)
    {
        if (services.Any(descriptor =>
                descriptor.ServiceType == typeof(IAshlarSecurityEventWebhookDeliveryObserver)
                && descriptor.ImplementationType == typeof(CompositeAshlarSecurityEventWebhookDeliveryObserver)))
        {
            return;
        }

        PreserveExistingWebhookDeliveryObservers(services);
        services.AddSingleton<IAshlarSecurityEventWebhookDeliveryObserver, CompositeAshlarSecurityEventWebhookDeliveryObserver>();
    }
}
