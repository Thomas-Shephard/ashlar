using Ashlar.Auditing;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Messaging;
using Ashlar.Operational;
using Ashlar.Postgres;
using Ashlar.Postgres.Schema;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Npgsql;

// ReSharper disable CheckNamespace
#pragma warning disable IDE0130
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130

public static class AshlarPostgresServiceCollectionExtensions
{
    /// <summary>
    /// Registers Ashlar PostgreSQL persistence services.
    /// </summary>
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
        services.TryAddTransient<SchemaManager>();

        return services;
    }

    /// <summary>
    /// Initializes the Ashlar PostgreSQL schema.
    /// </summary>
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
    public static IServiceCollection AddAshlarPostgresAuditSink(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarIdentity();
        services.Replace(ServiceDescriptor.Singleton<ISecurityEventSink, PostgresSecurityEventSink>());

        return services;
    }

    /// <summary>
    /// Registers the Ashlar PostgreSQL-backed email outbox sender.
    /// </summary>
    public static IServiceCollection AddAshlarPostgresEmailOutbox(
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
    /// <typeparam name="TTransport">The type of <see cref="IEmailTransport"/> to use for delivery.</typeparam>
    public static IServiceCollection AddAshlarPostgresEmailOutbox<TTransport>(
        this IServiceCollection services,
        Action<PostgresEmailOutboxOptions>? configure = null)
        where TTransport : class, IEmailTransport
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarPostgresEmailOutbox(configure);
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
    /// <typeparam name="TTransport">The type of <see cref="IEmailTransport"/> to use for delivery.</typeparam>
    public static IServiceCollection AddAshlarPostgresEmailOutboxHostedService<TTransport>(
        this IServiceCollection services,
        Action<PostgresEmailOutboxOptions>? configure = null)
        where TTransport : class, IEmailTransport
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarPostgresEmailOutbox<TTransport>(configure);
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, PostgresEmailOutboxHostedService>());

        return services;
    }
}
