using Ashlar.Auditing;
using Ashlar.Authorization.Abstractions;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Messaging;
using Ashlar.Operational;
using Ashlar.Sqlite.Schema;
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
    /// <param name="services">The services value.</param>
    /// <param name="connectionString">The SQLite connection string value.</param>
    /// <returns>The operation result.</returns>
    public static IServiceCollection AddAshlarSqlite(
        this IServiceCollection services,
        string connectionString)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);

        services.TryAddSingleton(new SqliteConnectionFactory(connectionString));
        services.TryAddScoped<SqliteTransactionManager>();
        services.Replace(ServiceDescriptor.Scoped<IAshlarTransactionProvider>(provider => provider.GetRequiredService<SqliteTransactionManager>()));
        services.TryAddScoped<ISqliteConnectionProvider>(provider => provider.GetRequiredService<SqliteTransactionManager>());
        services.TryAddScoped<IIdentityRepository, SqliteIdentityRepository>();
        services.TryAddScoped<IBootstrapStateRepository, SqliteBootstrapStateRepository>();
        services.TryAddScoped<IInvitationRepository, SqliteInvitationRepository>();
        services.TryAddScoped<IAuthenticationSessionRepository, SqliteAuthenticationSessionRepository>();
        services.TryAddScoped<IAuthenticationHandshakeRepository, SqliteAuthenticationHandshakeRepository>();
        services.TryAddScoped<IPasskeyChallengeRepository, SqlitePasskeyChallengeRepository>();
        services.TryAddScoped<IAuthorizationGrantRepository, SqliteAuthorizationGrantRepository>();
        services.Replace(ServiceDescriptor.Scoped<IAuthenticationRateLimiter, SqliteAuthenticationRateLimiter>());
        services.AddOptions<AshlarCleanupOptions>().Validate(AshlarCleanupOptions.Validate);
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddScoped<IAshlarCleanupService, SqliteAshlarCleanupService>();
        services.TryAddSingleton<SqliteSecurityEventSink>();
        services.Replace(ServiceDescriptor.Singleton<ISecurityEventSink>(provider => provider.GetRequiredService<SqliteSecurityEventSink>()));
        services.Replace(ServiceDescriptor.Singleton<IUserSecurityEventSummaryRepository>(provider => provider.GetRequiredService<SqliteSecurityEventSink>()));
        services.TryAddTransient<SqliteSchemaManager>();

        return services;
    }

    /// <summary>
    /// Initializes the Ashlar SQLite schema.
    /// </summary>
    /// <param name="serviceProvider">The service provider value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
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
    /// <param name="services">The services value.</param>
    /// <param name="configure">The configure value.</param>
    /// <returns>The operation result.</returns>
    public static IServiceCollection AddAshlarSqliteEmailOutboxSender(
        this IServiceCollection services,
        Action<SqliteEmailOutboxOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<SqliteEmailOutboxOptions>()
            .Validate(SqliteEmailOutboxOptions.Validate, "Email outbox options are invalid.");

        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddSingleton(TimeProvider.System);
        services.Replace(ServiceDescriptor.Scoped<IEmailSender, SqliteEmailOutboxSender>());

        return services;
    }

    /// <summary>
    /// Registers the Ashlar SQLite-backed email outbox sender and dispatcher.
    /// </summary>
    /// <typeparam name="TTransport">The transport type.</typeparam>
    /// <param name="services">The services value.</param>
    /// <param name="configure">The configure value.</param>
    /// <returns>The operation result.</returns>
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

        services.TryAddScoped<SqliteEmailOutboxDispatcher<TTransport>>();
        services.TryAddScoped<IEmailOutboxDispatcher>(provider => provider.GetRequiredService<SqliteEmailOutboxDispatcher<TTransport>>());

        return services;
    }

    /// <summary>
    /// Registers the Ashlar SQLite-backed email outbox dispatcher as a hosted service.
    /// </summary>
    /// <typeparam name="TTransport">The transport type.</typeparam>
    /// <param name="services">The services value.</param>
    /// <param name="configure">The configure value.</param>
    /// <returns>The operation result.</returns>
    public static IServiceCollection AddAshlarSqliteEmailOutboxHostedService<TTransport>(
        this IServiceCollection services,
        Action<SqliteEmailOutboxOptions>? configure = null)
        where TTransport : class, IEmailTransport
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarSqliteEmailOutboxDispatcher<TTransport>(configure);
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, SqliteEmailOutboxHostedService<TTransport>>());

        return services;
    }
}


