using Ashlar.Authorization.Abstractions;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Messaging;
using Ashlar.Operational;
using Ashlar.Operational.Diagnostics;
using Ashlar.Sqlite.Schema;
using Ashlar.Webhooks.SecurityEvents;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

// ReSharper disable CheckNamespace
#pragma warning disable IDE0130
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130

/// <summary>
/// Provides Ashlar SQLite service collection extensions.
/// </summary>
public static class AshlarSqliteServiceCollectionExtensions
{
    /// <summary>
    /// Registers Ashlar SQLite persistence infrastructure.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="connectionString">The SQLite connection string used by Ashlar persistence repositories.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    /// <remarks>An explicitly supplied Ashlar SQLite connection string replaces any earlier Ashlar SQLite connection factory registration.</remarks>
    public static IServiceCollection AddAshlarSqlite(
        this IServiceCollection services,
        string connectionString)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);

        services.Replace(ServiceDescriptor.Singleton(new SqliteConnectionFactory(connectionString)));
        services.TryAddScoped<SqliteTransactionManagerOwner>();
        services.TryAddScoped<ISqliteConnectionProvider>(provider =>
            provider.GetRequiredService<SqliteTransactionManagerOwner>());
        services.AddAshlarDurableTransactionProvider<SqliteTransactionManager>(provider =>
            provider.GetRequiredService<SqliteTransactionManagerOwner>().Value);
        services.TryAddAshlarProviderScoped<IUserRepository, SqliteUserRepository>();
        services.TryAddAshlarProviderScoped<ICredentialRepository, SqliteCredentialRepository>();
        services.TryAddAshlarProviderScoped<IAccountLockoutRepository, SqliteAccountLockoutRepository>();
        services.TryAddAshlarProviderScoped<IUserAdministrationRepository, SqliteUserAdministrationRepository>();
        services.TryAddAshlarProviderScoped<ICredentialAdministrationRepository, SqliteCredentialAdministrationRepository>();
        services.TryAddAshlarProviderScoped<ISecurityEventAdministrationRepository, SqliteSecurityEventAdministrationRepository>();
        services.TryAddAshlarProviderScoped<IAuthenticationSessionAdministrationRepository, SqliteAuthenticationSessionAdministrationRepository>();
        services.TryAddAshlarProviderScoped<IBootstrapStateRepository, SqliteBootstrapStateRepository>();
        services.TryAddAshlarProviderScoped<IInvitationRepository, SqliteInvitationRepository>();
        services.TryAddAshlarProviderScoped<IAuthenticationSessionRepository, SqliteAuthenticationSessionRepository>();
        services.TryAddAshlarProviderScoped<IAuthenticationHandshakeRepository, SqliteAuthenticationHandshakeRepository>();
        services.TryAddAshlarProviderScoped<IRememberedMfaDeviceRepository, SqliteRememberedMfaDeviceRepository>();
        services.TryAddAshlarProviderScoped<IPasskeyChallengeRepository, SqlitePasskeyChallengeRepository>();
        services.TryAddAshlarProviderScoped<IAuthorizationGrantRepository, SqliteAuthorizationGrantRepository>();
        services.TryAddAshlarProviderScoped<IAuthorizationGrantAdministrationRepository, SqliteAuthorizationGrantAdministrationRepository>();
        services.AddAshlarIdentityDurableTransactionParticipants();
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddScoped<IAshlarSchemaDiagnostics, SqliteSchemaDiagnostics>();
        services.TryAddTransient<SqliteSchemaManager>();

        return services;
    }

    /// <summary>
    /// Registers the Ashlar SQLite-backed security audit event sink.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarSqliteAuditSink(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarIdentity();
        services.TryAddAshlarProviderScoped<ISecurityEventAdministrationRepository, SqliteSecurityEventAdministrationRepository>();
        services.ReplaceAshlarProviderScoped<IPersistentSecurityEventSink>(provider =>
            ActivatorUtilities.CreateInstance<SqliteSecurityEventSink>(provider));
        services.AddAshlarDurableTransactionParticipant<IPersistentSecurityEventSink>();
        services.Replace(ServiceDescriptor.Scoped<IUserSecurityEventSummaryRepository, SqliteUserSecurityEventSummaryRepository>());

        return services;
    }

    /// <summary>
    /// Registers the Ashlar SQLite-backed authentication rate limiter, diagnostics, and safe administration operations.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarSqliteRateLimiting(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarAuthenticationRateLimitProviderMarker("SQLite");
        services.Replace(ServiceDescriptor.Scoped<IAuthenticationRateLimiter, SqliteAuthenticationRateLimiter>());
        services.Replace(ServiceDescriptor.Scoped<IAuthenticationRateLimiterDiagnostics, SqliteAuthenticationRateLimiterDiagnostics>());
        services.TryAddAshlarProviderScoped<IAuthenticationRateLimitAdministrationRepository, SqliteAuthenticationRateLimitAdministrationRepository>();
        services.AddAshlarDurableTransactionParticipant<IAuthenticationRateLimitAdministrationRepository>();
        services.AddAshlarAuthenticationRateLimitAdministration();

        return services;
    }

    /// <summary>
    /// Registers the Ashlar SQLite cleanup service for explicit cleanup calls.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional cleanup configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarSqliteCleanup(
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
        services.TryAddScoped<IAshlarCleanupDiagnostics, SqliteAshlarCleanupDiagnostics>();
        services.TryAddScoped<IAshlarCleanupService, SqliteAshlarCleanupService>();

        return services;
    }

    /// <summary>
    /// Registers the Ashlar SQLite cleanup service and starts a hosted cleanup loop.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional cleanup configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarSqliteCleanupHostedService(
        this IServiceCollection services,
        Action<AshlarCleanupOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarSqliteCleanup(configure);
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, SqliteAshlarCleanupHostedService>());

        return services;
    }

    /// <summary>
    /// Initializes the Ashlar SQLite schema.
    /// </summary>
    /// <param name="serviceProvider">The root service provider containing SQLite schema services.</param>
    /// <param name="cancellationToken">A token that can cancel schema initialization.</param>
    /// <returns>A task that completes when the schema has been initialized.</returns>
    public static async Task InitializeAshlarSqliteSchemaAsync(this IServiceProvider serviceProvider, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(serviceProvider);

        using var scope = serviceProvider.CreateScope();
        var schemaManager = scope.ServiceProvider.GetRequiredService<SqliteSchemaManager>();
        await schemaManager.InitializeAsync(cancellationToken);
    }

    /// <summary>
    /// Registers the Ashlar SQLite-backed email outbox enqueue sender.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional email outbox configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarSqliteEmailOutboxSender(
        this IServiceCollection services,
        Action<SqliteEmailOutboxOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<SqliteEmailOutboxOptions>()
            .Validate(SqliteEmailOutboxOptions.Validate, "Email outbox options are invalid.")
            .ValidateOnStart();

        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddSingleton(TimeProvider.System);
        services.Replace(ServiceDescriptor.Scoped<IEmailOutboxAdministrationService>(provider => new SqliteEmailOutboxAdministrationService(
            provider.GetRequiredService<ISqliteConnectionProvider>(),
            provider.GetRequiredService<TimeProvider>(),
            provider.GetRequiredService<ISecurityEventSink>(),
            provider.GetRequiredService<AshlarDurableTransactionProvider>())));
        services.Replace(ServiceDescriptor.Scoped<IEmailOutboxDiagnostics, SqliteEmailOutboxDiagnostics>());
        services.Replace(ServiceDescriptor.Scoped<IEmailSender, SqliteEmailOutboxSender>());

        return services;
    }

    /// <summary>
    /// Registers the Ashlar SQLite-backed email outbox sender and dispatcher.
    /// </summary>
    /// <typeparam name="TTransport">The email transport used to deliver queued messages.</typeparam>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional email outbox configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarSqliteEmailOutboxDispatcher<TTransport>(
        this IServiceCollection services,
        Action<SqliteEmailOutboxOptions>? configure = null)
        where TTransport : class, IEmailTransport
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarSqliteEmailOutboxSender(configure);
        if (!typeof(TTransport).IsInterface && !typeof(TTransport).IsAbstract)
        {
            services.TryAddScoped<TTransport>();
        }

        services.TryAddScoped<IEmailOutboxDispatcher, SqliteEmailOutboxDispatcher<TTransport>>();

        return services;
    }

    /// <summary>
    /// Registers the Ashlar SQLite-backed email outbox dispatcher as a hosted service.
    /// </summary>
    /// <typeparam name="TTransport">The email transport used by the hosted dispatcher.</typeparam>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional email outbox configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarSqliteEmailOutboxHostedService<TTransport>(
        this IServiceCollection services,
        Action<SqliteEmailOutboxOptions>? configure = null)
        where TTransport : class, IEmailTransport
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarSqliteEmailOutboxDispatcher<TTransport>(configure);
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, SqliteEmailOutboxHostedService>());

        return services;
    }

    /// <summary>
    /// Registers the Ashlar SQLite-backed security event webhook outbox enqueuer.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional webhook outbox configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarSqliteSecurityEventWebhookOutbox(
        this IServiceCollection services,
        Action<SqliteSecurityEventWebhookOutboxOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarSecurityEventWebhookOutbox();
        services.AddOptions<SqliteSecurityEventWebhookOutboxOptions>()
            .Validate(SqliteSecurityEventWebhookOutboxOptions.Validate, "Security event webhook outbox options are invalid.")
            .ValidateOnStart();

        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddAshlarProviderScoped<SqliteSecurityEventWebhookEnqueuer, SqliteSecurityEventWebhookEnqueuer>();
        services.AddAshlarDurableSecurityEventFanOutHandler<SqliteSecurityEventWebhookEnqueuer>();
        services.Replace(ServiceDescriptor.Scoped<IAshlarSecurityEventWebhookOutboxOperations>(provider => new SqliteSecurityEventWebhookOutboxOperations(
            provider.GetRequiredService<ISqliteConnectionProvider>(),
            provider.GetRequiredService<TimeProvider>(),
            provider.GetRequiredService<ISecurityEventSink>(),
            provider.GetRequiredService<AshlarDurableTransactionProvider>(),
            provider.GetRequiredService<IAuthenticationSessionRepository>(),
            provider.GetRequiredService<IAccountSecurityOperationAuthorizer>(),
            provider.GetRequiredService<IPersistentSecurityEventSink>())));
        services.Replace(ServiceDescriptor.Scoped<IAshlarSecurityEventWebhookOutboxBrowser, SqliteSecurityEventWebhookOutboxBrowser>());
        services.Replace(ServiceDescriptor.Scoped<ISecurityEventWebhookOutboxDiagnostics, SqliteSecurityEventWebhookOutboxDiagnostics>());

        return services;
    }

    /// <summary>
    /// Registers the Ashlar SQLite-backed security event webhook outbox enqueuer and dispatcher.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional webhook outbox configuration.</param>
    /// <param name="configureWebhooks">Optional webhook destination configuration.</param>
    /// <param name="configureHttpClient">Optional <see cref="HttpClient" /> configuration. The primary handler is Ashlar-owned.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarSqliteSecurityEventWebhookDispatcher(
        this IServiceCollection services,
        Action<SqliteSecurityEventWebhookOutboxOptions>? configure = null,
        Action<AshlarSecurityEventWebhookOptions>? configureWebhooks = null,
        Action<HttpClient>? configureHttpClient = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarSecurityEventWebhookOutbox(configureWebhooks, configureHttpClient);
        services.AddAshlarSqliteSecurityEventWebhookOutbox(configure);
        services.TryAddScoped<SqliteSecurityEventWebhookOutboxDispatcher>();

        return services;
    }

    /// <summary>
    /// Registers the Ashlar SQLite-backed security event webhook outbox dispatcher as a hosted service.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional webhook outbox configuration.</param>
    /// <param name="configureWebhooks">Optional webhook destination configuration.</param>
    /// <param name="configureHttpClient">Optional <see cref="HttpClient" /> configuration. The primary handler is Ashlar-owned.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarSqliteSecurityEventWebhookHostedService(
        this IServiceCollection services,
        Action<SqliteSecurityEventWebhookOutboxOptions>? configure = null,
        Action<AshlarSecurityEventWebhookOptions>? configureWebhooks = null,
        Action<HttpClient>? configureHttpClient = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarSqliteSecurityEventWebhookDispatcher(configure, configureWebhooks, configureHttpClient);
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, SqliteSecurityEventWebhookOutboxHostedService>());

        return services;
    }
}
