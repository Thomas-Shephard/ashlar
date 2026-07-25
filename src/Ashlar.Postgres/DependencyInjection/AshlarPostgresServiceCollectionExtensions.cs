using Ashlar.Authorization.Abstractions;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Messaging;
using Ashlar.Operational;
using Ashlar.Operational.Diagnostics;
using Ashlar.Postgres.Schema;
using Ashlar.Webhooks.SecurityEvents;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Npgsql;

// ReSharper disable CheckNamespace
#pragma warning disable IDE0130
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130

/// <summary>
/// Provides dependency injection registration methods for Ashlar PostgreSQL integrations.
/// </summary>
public static class AshlarPostgresServiceCollectionExtensions
{
    /// <summary>
    /// Registers Ashlar PostgreSQL persistence services.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="connectionString">The PostgreSQL connection string used to create an <see cref="NpgsqlDataSource"/>.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    /// <remarks>An explicitly supplied Ashlar PostgreSQL connection replaces any earlier <see cref="NpgsqlDataSource"/> registration.</remarks>
    public static IServiceCollection AddAshlarPostgres(
        this IServiceCollection services,
        string connectionString)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);

        services.ReplacePostgresDataSource(connectionString);
        return services.AddAshlarPostgresPersistence();
    }

    /// <summary>
    /// Registers Ashlar PostgreSQL persistence services using a provided <see cref="NpgsqlDataSource"/>.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="dataSource">The PostgreSQL data source used by Ashlar persistence repositories.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    /// <remarks>An explicitly supplied Ashlar PostgreSQL data source replaces any earlier <see cref="NpgsqlDataSource"/> registration.</remarks>
    public static IServiceCollection AddAshlarPostgres(
        this IServiceCollection services,
        NpgsqlDataSource dataSource)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(dataSource);

        services.ReplacePostgresDataSource(dataSource);
        return services.AddAshlarPostgresPersistence();
    }

    private static IServiceCollection AddAshlarPostgresPersistence(this IServiceCollection services)
    {
        services.AddPostgresTransactionServices();
        services.TryAddAshlarProviderScoped<IUserRepository, PostgresUserRepository>();
        services.TryAddAshlarProviderScoped<ICredentialRepository, PostgresCredentialRepository>();
        services.TryAddAshlarProviderScoped<IAccountLockoutRepository, PostgresAccountLockoutRepository>();
        services.TryAddAshlarProviderScoped<IUserAdministrationRepository, PostgresUserAdministrationRepository>();
        services.TryAddAshlarProviderScoped<ICredentialAdministrationRepository, PostgresCredentialAdministrationRepository>();
        services.TryAddAshlarProviderScoped<ISecurityEventAdministrationRepository, PostgresSecurityEventAdministrationRepository>();
        services.TryAddAshlarProviderScoped<IAuthenticationSessionAdministrationRepository, PostgresAuthenticationSessionAdministrationRepository>();
        services.TryAddAshlarProviderScoped<IInvitationRepository, PostgresInvitationRepository>();
        services.TryAddAshlarProviderScoped<IAuthenticationSessionRepository, PostgresAuthenticationSessionRepository>();
        services.TryAddAshlarProviderScoped<IAuthenticationHandshakeRepository, PostgresAuthenticationHandshakeRepository>();
        services.TryAddAshlarProviderScoped<IRememberedMfaDeviceRepository, PostgresRememberedMfaDeviceRepository>();
        services.TryAddAshlarProviderScoped<IPasskeyChallengeRepository, PostgresPasskeyChallengeRepository>();
        services.TryAddAshlarProviderScoped<IAuthorizationGrantRepository, PostgresAuthorizationGrantRepository>();
        services.TryAddAshlarProviderScoped<IAuthorizationGrantAdministrationRepository, PostgresAuthorizationGrantAdministrationRepository>();
        services.AddAshlarIdentityDurableTransactionParticipants();
        services.TryAddAshlarProviderScoped<IBootstrapStateRepository, PostgresBootstrapStateRepository>();
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddScoped<IAshlarSchemaDiagnostics, PostgresSchemaDiagnostics>();
        services.TryAddTransient<SchemaManager>();

        return services;
    }

    /// <summary>
    /// Registers Ashlar PostgreSQL-backed bootstrap persistence.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="connectionString">The PostgreSQL connection string used to create an <see cref="NpgsqlDataSource"/>.</param>
    /// <param name="configure">Optional bootstrap configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    /// <remarks>An explicitly supplied Ashlar PostgreSQL connection replaces any earlier <see cref="NpgsqlDataSource"/> registration.</remarks>
    public static IServiceCollection AddAshlarPostgresBootstrap(
        this IServiceCollection services,
        string connectionString,
        Action<BootstrapOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);

        services.ReplacePostgresDataSource(connectionString);
        return services.AddAshlarPostgresBootstrapPersistence(configure);
    }

    /// <summary>
    /// Registers Ashlar PostgreSQL-backed bootstrap persistence using a provided <see cref="NpgsqlDataSource"/>.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="dataSource">The PostgreSQL data source used by bootstrap persistence.</param>
    /// <param name="configure">Optional bootstrap configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    /// <remarks>An explicitly supplied Ashlar PostgreSQL data source replaces any earlier <see cref="NpgsqlDataSource"/> registration.</remarks>
    public static IServiceCollection AddAshlarPostgresBootstrap(
        this IServiceCollection services,
        NpgsqlDataSource dataSource,
        Action<BootstrapOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(dataSource);

        services.ReplacePostgresDataSource(dataSource);
        return services.AddAshlarPostgresBootstrapPersistence(configure);
    }

    private static IServiceCollection AddAshlarPostgresBootstrapPersistence(
        this IServiceCollection services,
        Action<BootstrapOptions>? configure = null)
    {
        services.AddAshlarBootstrap(configure);
        services.AddPostgresTransactionServices();
        services.TryAddAshlarProviderScoped<IBootstrapStateRepository, PostgresBootstrapStateRepository>();

        return services;
    }

    /// <summary>
    /// Registers Ashlar PostgreSQL-backed authorization persistence.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="connectionString">The PostgreSQL connection string used to create an <see cref="NpgsqlDataSource"/>.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    /// <remarks>An explicitly supplied Ashlar PostgreSQL connection replaces any earlier <see cref="NpgsqlDataSource"/> registration.</remarks>
    public static IServiceCollection AddAshlarPostgresAuthorization(
        this IServiceCollection services,
        string connectionString)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);

        services.ReplacePostgresDataSource(connectionString);
        return services.AddAshlarPostgresAuthorizationPersistence();
    }

    /// <summary>
    /// Registers Ashlar PostgreSQL-backed authorization persistence using a provided <see cref="NpgsqlDataSource"/>.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="dataSource">The PostgreSQL data source used by authorization persistence.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    /// <remarks>An explicitly supplied Ashlar PostgreSQL data source replaces any earlier <see cref="NpgsqlDataSource"/> registration.</remarks>
    public static IServiceCollection AddAshlarPostgresAuthorization(
        this IServiceCollection services,
        NpgsqlDataSource dataSource)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(dataSource);

        services.ReplacePostgresDataSource(dataSource);
        return services.AddAshlarPostgresAuthorizationPersistence();
    }

    private static IServiceCollection AddAshlarPostgresAuthorizationPersistence(this IServiceCollection services)
    {
        services.AddAshlarAuthorization();
        services.AddPostgresTransactionServices();
        services.TryAddAshlarProviderScoped<IAuthorizationGrantRepository, PostgresAuthorizationGrantRepository>();
        services.TryAddAshlarProviderScoped<IAuthorizationGrantAdministrationRepository, PostgresAuthorizationGrantAdministrationRepository>();
        services.AddAshlarDurableTransactionParticipant<IAuthorizationGrantRepository>();

        return services;
    }

    private static void ReplacePostgresDataSource(this IServiceCollection services, string connectionString)
    {
        services.Replace(ServiceDescriptor.Singleton(_ => new NpgsqlDataSourceBuilder(connectionString).Build()));
    }

    private static void ReplacePostgresDataSource(this IServiceCollection services, NpgsqlDataSource dataSource)
    {
        services.Replace(ServiceDescriptor.Singleton(dataSource));
    }

    private static void AddPostgresTransactionServices(this IServiceCollection services)
    {
        services.TryAddScoped<PostgresTransactionManagerOwner>();
        services.TryAddScoped<IPostgresConnectionProvider>(provider =>
            provider.GetRequiredService<PostgresTransactionManagerOwner>());
        services.AddAshlarDurableTransactionProvider<PostgresTransactionManager>(provider =>
            provider.GetRequiredService<PostgresTransactionManagerOwner>().Value);
    }

    /// <summary>
    /// Initializes the Ashlar PostgreSQL schema.
    /// </summary>
    /// <param name="serviceProvider">The root service provider containing PostgreSQL schema services.</param>
    /// <param name="cancellationToken">A token that can cancel schema initialization.</param>
    /// <returns>A task that completes when the schema has been initialized.</returns>
    public static async Task InitializeAshlarPostgresSchemaAsync(this IServiceProvider serviceProvider, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(serviceProvider);

        using var scope = serviceProvider.CreateScope();
        var schemaManager = scope.ServiceProvider.GetRequiredService<SchemaManager>();
        await schemaManager.InitializeAsync(cancellationToken);
    }

    /// <summary>
    /// Registers the Ashlar PostgreSQL-backed authentication rate limiter, diagnostics, and safe administration operations.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional rate limiter configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarPostgresRateLimiting(
        this IServiceCollection services,
        Action<PostgresAuthenticationRateLimiterOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<PostgresAuthenticationRateLimiterOptions>()
            .Validate(PostgresAuthenticationRateLimiter.ValidateOptions, "CleanupInterval must be greater than zero and MaxCleanupRows must be greater than zero.")
            .ValidateOnStart();

        if (configure != null)
        {
            services.Configure(configure);
        }

        services.Replace(ServiceDescriptor.Singleton<IAuthenticationRateLimiter, PostgresAuthenticationRateLimiter>());
        services.Replace(ServiceDescriptor.Scoped<IAuthenticationRateLimiterDiagnostics, PostgresAuthenticationRateLimiterDiagnostics>());
        services.TryAddAshlarProviderScoped<IAuthenticationRateLimitAdministrationRepository, PostgresAuthenticationRateLimitAdministrationRepository>();
        services.AddAshlarDurableTransactionParticipant<IAuthenticationRateLimitAdministrationRepository>();
        services.AddAshlarAuthenticationRateLimitAdministration();

        return services;
    }

    /// <summary>
    /// Registers the Ashlar PostgreSQL cleanup service for explicit cleanup calls.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional cleanup configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarPostgresCleanup(
        this IServiceCollection services,
        Action<AshlarCleanupOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<AshlarCleanupOptions>()
            .Validate(AshlarCleanupOptions.Validate, "Cleanup options are invalid.")
            .ValidateOnStart();

        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddScoped<IAshlarCleanupDiagnostics, PostgresAshlarCleanupDiagnostics>();
        services.TryAddScoped<IAshlarCleanupService, PostgresAshlarCleanupService>();

        return services;
    }

    /// <summary>
    /// Registers the Ashlar PostgreSQL cleanup service and starts a hosted cleanup loop.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional cleanup configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarPostgresCleanupHostedService(
        this IServiceCollection services,
        Action<AshlarCleanupOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarPostgresCleanup(configure);
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, PostgresAshlarCleanupHostedService>());

        return services;
    }

    /// <summary>
    /// Registers the Ashlar PostgreSQL-backed security audit event sink.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarPostgresAuditSink(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarIdentity();
        services.TryAddAshlarProviderScoped<ISecurityEventAdministrationRepository, PostgresSecurityEventAdministrationRepository>();
        services.ReplaceAshlarProviderScoped<IPersistentSecurityEventSink>(provider =>
            ActivatorUtilities.CreateInstance<PostgresSecurityEventSink>(provider));
        services.AddAshlarDurableTransactionParticipant<IPersistentSecurityEventSink>();
        services.Replace(ServiceDescriptor.Scoped<IUserSecurityEventSummaryRepository, PostgresUserSecurityEventSummaryRepository>());

        return services;
    }

    /// <summary>
    /// Registers the Ashlar PostgreSQL-backed email outbox enqueue sender.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional email outbox configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarPostgresEmailOutboxSender(
        this IServiceCollection services,
        Action<PostgresEmailOutboxOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<PostgresEmailOutboxOptions>()
            .Validate(PostgresEmailOutboxOptions.Validate, "Email outbox options are invalid.")
            .ValidateOnStart();

        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddSingleton(TimeProvider.System);
        services.Replace(ServiceDescriptor.Scoped<IEmailOutboxAdministrationService>(provider => new PostgresEmailOutboxAdministrationService(
            provider.GetRequiredService<IPostgresConnectionProvider>(),
            provider.GetRequiredService<TimeProvider>(),
            provider.GetRequiredService<ISecurityEventSink>(),
            provider.GetRequiredService<AshlarDurableTransactionProvider>())));
        services.Replace(ServiceDescriptor.Scoped<IEmailOutboxDiagnostics, PostgresEmailOutboxDiagnostics>());
        services.Replace(ServiceDescriptor.Scoped<IEmailSender, PostgresEmailOutboxSender>());

        return services;
    }

    /// <summary>
    /// Registers the Ashlar PostgreSQL-backed email outbox sender and dispatcher.
    /// </summary>
    /// <typeparam name="TTransport">The email transport used to deliver queued messages.</typeparam>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional email outbox configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarPostgresEmailOutboxDispatcher<TTransport>(
        this IServiceCollection services,
        Action<PostgresEmailOutboxOptions>? configure = null)
        where TTransport : class, IEmailTransport
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarPostgresEmailOutboxSender(configure);
        if (!typeof(TTransport).IsInterface && !typeof(TTransport).IsAbstract)
        {
            services.TryAddScoped<TTransport>();
        }
        services.TryAddScoped<IEmailOutboxDispatcher, PostgresEmailOutboxDispatcher<TTransport>>();

        return services;
    }

    /// <summary>
    /// Registers the Ashlar PostgreSQL-backed email outbox dispatcher as a hosted service.
    /// </summary>
    /// <typeparam name="TTransport">The email transport used by the hosted dispatcher.</typeparam>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional email outbox configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarPostgresEmailOutboxHostedService<TTransport>(
        this IServiceCollection services,
        Action<PostgresEmailOutboxOptions>? configure = null)
        where TTransport : class, IEmailTransport
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarPostgresEmailOutboxDispatcher<TTransport>(configure);
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, PostgresEmailOutboxHostedService>());

        return services;
    }

    /// <summary>
    /// Registers the Ashlar PostgreSQL-backed security event webhook outbox enqueuer.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional webhook outbox configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarPostgresSecurityEventWebhookOutbox(
        this IServiceCollection services,
        Action<PostgresSecurityEventWebhookOutboxOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarSecurityEventWebhookOutbox();
        services.AddOptions<PostgresSecurityEventWebhookOutboxOptions>()
            .Validate(PostgresSecurityEventWebhookOutboxOptions.Validate, "Security event webhook outbox options are invalid.")
            .ValidateOnStart();

        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddAshlarProviderScoped<PostgresSecurityEventWebhookEnqueuer, PostgresSecurityEventWebhookEnqueuer>();
        services.AddAshlarDurableSecurityEventFanOutHandler<PostgresSecurityEventWebhookEnqueuer>();
        services.Replace(ServiceDescriptor.Scoped<IAshlarSecurityEventWebhookOutboxOperations>(provider => new PostgresSecurityEventWebhookOutboxOperations(
            provider.GetRequiredService<IPostgresConnectionProvider>(),
            provider.GetRequiredService<TimeProvider>(),
            provider.GetRequiredService<ISecurityEventSink>(),
            provider.GetRequiredService<AshlarDurableTransactionProvider>(),
            provider.GetRequiredService<IAuthenticationSessionRepository>(),
            provider.GetRequiredService<IAccountSecurityOperationAuthorizer>(),
            provider.GetRequiredService<IPersistentSecurityEventSink>())));
        services.Replace(ServiceDescriptor.Scoped<IAshlarSecurityEventWebhookOutboxBrowser, PostgresSecurityEventWebhookOutboxBrowser>());
        services.Replace(ServiceDescriptor.Scoped<ISecurityEventWebhookOutboxDiagnostics, PostgresSecurityEventWebhookOutboxDiagnostics>());

        return services;
    }

    /// <summary>
    /// Registers the Ashlar PostgreSQL-backed security event webhook outbox enqueuer and dispatcher.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional webhook outbox configuration.</param>
    /// <param name="configureWebhooks">Optional webhook destination configuration.</param>
    /// <param name="configureHttpClient">Optional <see cref="HttpClient" /> configuration. The primary handler is Ashlar-owned.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarPostgresSecurityEventWebhookDispatcher(
        this IServiceCollection services,
        Action<PostgresSecurityEventWebhookOutboxOptions>? configure = null,
        Action<AshlarSecurityEventWebhookOptions>? configureWebhooks = null,
        Action<HttpClient>? configureHttpClient = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarPostgresSecurityEventWebhookOutbox(configure);
        services.AddOptions<AshlarSecurityEventWebhookOptions>()
            .Validate(AshlarSecurityEventWebhookOptions.Validate, "Ashlar security event webhook options are invalid.")
            .ValidateOnStart();
        if (configureWebhooks != null)
        {
            services.Configure(configureWebhooks);
        }

        services.TryAddSingleton<IAshlarSecurityEventWebhookDestinationResolver, DnsAshlarSecurityEventWebhookDestinationResolver>();
        services.TryAddSingleton<AshlarSecurityEventWebhookDestinationValidator>();
        var httpClientBuilder = services.AddHttpClient(PostgresSecurityEventWebhookOutboxDispatcher.HttpClientName)
            .ConfigurePrimaryHttpMessageHandler(CreateWebhookHttpMessageHandler);
        if (configureHttpClient != null)
        {
            httpClientBuilder.ConfigureHttpClient(configureHttpClient);
        }
        services.TryAddScoped<PostgresSecurityEventWebhookOutboxDispatcher>();

        return services;
    }

    /// <summary>
    /// Registers the Ashlar PostgreSQL-backed security event webhook outbox dispatcher as a hosted service.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional webhook outbox configuration.</param>
    /// <param name="configureWebhooks">Optional webhook destination configuration.</param>
    /// <param name="configureHttpClient">Optional <see cref="HttpClient" /> configuration. The primary handler is Ashlar-owned.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarPostgresSecurityEventWebhookHostedService(
        this IServiceCollection services,
        Action<PostgresSecurityEventWebhookOutboxOptions>? configure = null,
        Action<AshlarSecurityEventWebhookOptions>? configureWebhooks = null,
        Action<HttpClient>? configureHttpClient = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarPostgresSecurityEventWebhookDispatcher(configure, configureWebhooks, configureHttpClient);
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, PostgresSecurityEventWebhookOutboxHostedService>());

        return services;
    }

    private static HttpMessageHandler CreateWebhookHttpMessageHandler(IServiceProvider provider)
    {
        var destinationValidator = provider.GetRequiredService<AshlarSecurityEventWebhookDestinationValidator>();
        return AshlarSecurityEventWebhookHttpMessageHandlerFactory.Create(destinationValidator);
    }
}
