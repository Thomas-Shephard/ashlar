using Ashlar.Auditing;
using Ashlar.Authorization.Abstractions;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Messaging;
using Ashlar.Operational;
using Ashlar.Postgres.Schema;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Npgsql;

// ReSharper disable CheckNamespace
#pragma warning disable IDE0130
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130

/// <summary>
/// Provides ashlar postgres service collection extensions behavior.
/// </summary>
public static class AshlarPostgresServiceCollectionExtensions
{
    /// <summary>
    /// Registers Ashlar PostgreSQL persistence services.
    /// </summary>
    /// <param name="services">The services value.</param>
    /// <param name="connectionString">The connection string value.</param>
    /// <returns>The operation result.</returns>
    public static IServiceCollection AddAshlarPostgres(
        this IServiceCollection services,
        string connectionString)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);

        services.TryAddSingleton(_ => new NpgsqlDataSourceBuilder(connectionString).Build());
        return services.AddAshlarPostgresPersistence();
    }

    /// <summary>
    /// Registers Ashlar PostgreSQL persistence services using a provided <see cref="NpgsqlDataSource"/>.
    /// </summary>
    /// <param name="services">The services value.</param>
    /// <param name="dataSource">The data source value.</param>
    /// <returns>The operation result.</returns>
    public static IServiceCollection AddAshlarPostgres(
        this IServiceCollection services,
        NpgsqlDataSource dataSource)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(dataSource);

        services.TryAddSingleton(dataSource);
        return services.AddAshlarPostgresPersistence();
    }

    private static IServiceCollection AddAshlarPostgresPersistence(this IServiceCollection services)
    {
        services.TryAddScoped<PostgresTransactionManager>();
        services.Replace(ServiceDescriptor.Scoped<IAshlarTransactionProvider>(provider => provider.GetRequiredService<PostgresTransactionManager>()));
        services.TryAddScoped<IPostgresConnectionProvider>(provider => provider.GetRequiredService<PostgresTransactionManager>());
        services.TryAddScoped<IIdentityRepository, PostgresIdentityRepository>();
        services.TryAddScoped<IInvitationRepository, PostgresInvitationRepository>();
        services.TryAddScoped<IAuthenticationSessionRepository, PostgresAuthenticationSessionRepository>();
        services.TryAddScoped<IAuthenticationHandshakeRepository, PostgresAuthenticationHandshakeRepository>();
        services.TryAddScoped<IPasskeyChallengeRepository, PostgresPasskeyChallengeRepository>();
        services.TryAddScoped<IAuthorizationGrantRepository, PostgresAuthorizationGrantRepository>();
        services.TryAddScoped<IBootstrapStateRepository, PostgresBootstrapStateRepository>();
        services.TryAddTransient<SchemaManager>();

        return services;
    }

    /// <summary>
    /// Registers Ashlar PostgreSQL-backed bootstrap persistence.
    /// </summary>
    /// <param name="services">The services value.</param>
    /// <param name="connectionString">The connection string value.</param>
    /// <param name="configure">The configure value.</param>
    /// <returns>The operation result.</returns>
    public static IServiceCollection AddAshlarPostgresBootstrap(
        this IServiceCollection services,
        string connectionString,
        Action<BootstrapOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);

        services.TryAddSingleton(_ => new NpgsqlDataSourceBuilder(connectionString).Build());
        return services.AddAshlarPostgresBootstrapPersistence(configure);
    }

    /// <summary>
    /// Registers Ashlar PostgreSQL-backed bootstrap persistence using a provided <see cref="NpgsqlDataSource"/>.
    /// </summary>
    /// <param name="services">The services value.</param>
    /// <param name="dataSource">The data source value.</param>
    /// <param name="configure">The configure value.</param>
    /// <returns>The operation result.</returns>
    public static IServiceCollection AddAshlarPostgresBootstrap(
        this IServiceCollection services,
        NpgsqlDataSource dataSource,
        Action<BootstrapOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(dataSource);

        services.TryAddSingleton(dataSource);
        return services.AddAshlarPostgresBootstrapPersistence(configure);
    }

    private static IServiceCollection AddAshlarPostgresBootstrapPersistence(
        this IServiceCollection services,
        Action<BootstrapOptions>? configure = null)
    {
        services.AddAshlarBootstrap(configure);
        services.TryAddScoped<PostgresTransactionManager>();
        services.Replace(ServiceDescriptor.Scoped<IAshlarTransactionProvider>(provider => provider.GetRequiredService<PostgresTransactionManager>()));
        services.TryAddScoped<IPostgresConnectionProvider>(provider => provider.GetRequiredService<PostgresTransactionManager>());
        services.TryAddScoped<IBootstrapStateRepository, PostgresBootstrapStateRepository>();

        return services;
    }

    /// <summary>
    /// Registers Ashlar PostgreSQL-backed authorization persistence.
    /// </summary>
    /// <param name="services">The services value.</param>
    /// <param name="connectionString">The connection string value.</param>
    /// <returns>The operation result.</returns>
    public static IServiceCollection AddAshlarPostgresAuthorization(
        this IServiceCollection services,
        string connectionString)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);

        services.TryAddSingleton(_ => new NpgsqlDataSourceBuilder(connectionString).Build());
        return services.AddAshlarPostgresAuthorizationPersistence();
    }

    /// <summary>
    /// Registers Ashlar PostgreSQL-backed authorization persistence using a provided <see cref="NpgsqlDataSource"/>.
    /// </summary>
    /// <param name="services">The services value.</param>
    /// <param name="dataSource">The data source value.</param>
    /// <returns>The operation result.</returns>
    public static IServiceCollection AddAshlarPostgresAuthorization(
        this IServiceCollection services,
        NpgsqlDataSource dataSource)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(dataSource);

        services.TryAddSingleton(dataSource);
        return services.AddAshlarPostgresAuthorizationPersistence();
    }

    private static IServiceCollection AddAshlarPostgresAuthorizationPersistence(this IServiceCollection services)
    {
        services.AddAshlarAuthorization();
        services.TryAddScoped<PostgresTransactionManager>();
        services.TryAddScoped<IPostgresConnectionProvider>(provider => provider.GetRequiredService<PostgresTransactionManager>());
        services.TryAddScoped<IAuthorizationGrantRepository, PostgresAuthorizationGrantRepository>();

        return services;
    }

    /// <summary>
    /// Initializes the Ashlar PostgreSQL schema.
    /// </summary>
    /// <param name="serviceProvider">The service provider value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public static async Task InitializeAshlarPostgresSchemaAsync(this IServiceProvider serviceProvider, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(serviceProvider);

        using var scope = serviceProvider.CreateScope();
        var schemaManager = scope.ServiceProvider.GetRequiredService<SchemaManager>();
        await schemaManager.InitializeAsync(cancellationToken);
    }

    /// <summary>
    /// Registers the Ashlar PostgreSQL-backed authentication rate limiter.
    /// </summary>
    /// <param name="services">The services value.</param>
    /// <param name="configure">The configure value.</param>
    /// <returns>The operation result.</returns>
    public static IServiceCollection AddAshlarPostgresRateLimiting(
        this IServiceCollection services,
        Action<PostgresAuthenticationRateLimiterOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<PostgresAuthenticationRateLimiterOptions>()
            .Validate(PostgresAuthenticationRateLimiter.ValidateOptions, "CleanupInterval must be greater than zero and MaxCleanupRows must be greater than zero.");

        if (configure != null)
        {
            services.Configure(configure);
        }

        services.Replace(ServiceDescriptor.Singleton<IAuthenticationRateLimiter, PostgresAuthenticationRateLimiter>());

        return services;
    }

    /// <summary>
    /// Registers the Ashlar PostgreSQL cleanup service for explicit cleanup calls.
    /// </summary>
    /// <param name="services">The services value.</param>
    /// <param name="configure">The configure value.</param>
    /// <returns>The operation result.</returns>
    public static IServiceCollection AddAshlarPostgresCleanup(
        this IServiceCollection services,
        Action<AshlarCleanupOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<AshlarCleanupOptions>()
            .Validate(AshlarCleanupOptions.Validate, "Cleanup options are invalid.");

        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddScoped<IAshlarCleanupService, PostgresAshlarCleanupService>();

        return services;
    }

    /// <summary>
    /// Registers the Ashlar PostgreSQL cleanup service and starts a hosted cleanup loop.
    /// </summary>
    /// <param name="services">The services value.</param>
    /// <param name="configure">The configure value.</param>
    /// <returns>The operation result.</returns>
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
    /// <param name="services">The services value.</param>
    /// <returns>The operation result.</returns>
    public static IServiceCollection AddAshlarPostgresAuditSink(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarIdentity();
        services.TryAddSingleton<PostgresSecurityEventSink>();
        services.Replace(ServiceDescriptor.Singleton<ISecurityEventSink>(provider => provider.GetRequiredService<PostgresSecurityEventSink>()));
        services.Replace(ServiceDescriptor.Singleton<IUserSecurityEventSummaryRepository>(provider => provider.GetRequiredService<PostgresSecurityEventSink>()));

        return services;
    }

    /// <summary>
    /// Registers the Ashlar PostgreSQL-backed email outbox enqueue sender.
    /// </summary>
    /// <param name="services">The services value.</param>
    /// <param name="configure">The configure value.</param>
    /// <returns>The operation result.</returns>
    public static IServiceCollection AddAshlarPostgresEmailOutboxSender(
        this IServiceCollection services,
        Action<PostgresEmailOutboxOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<PostgresEmailOutboxOptions>()
            .Validate(PostgresEmailOutboxOptions.Validate, "Email outbox options are invalid.");

        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddSingleton(TimeProvider.System);
        services.Replace(ServiceDescriptor.Scoped<IEmailSender, PostgresEmailOutboxSender>());

        return services;
    }

    /// <summary>
    /// Registers the Ashlar PostgreSQL-backed email outbox sender and dispatcher.
    /// </summary>
    /// <typeparam name="TTransport">The ttransport type.</typeparam>
    /// <param name="services">The services value.</param>
    /// <param name="configure">The configure value.</param>
    /// <returns>The operation result.</returns>
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
    /// <typeparam name="TTransport">The ttransport type.</typeparam>
    /// <param name="services">The services value.</param>
    /// <param name="configure">The configure value.</param>
    /// <returns>The operation result.</returns>
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
}


