using Ashlar.Identity.Abstractions;
using Ashlar.Sqlite;
using Ashlar.Sqlite.Schema;
using Microsoft.Extensions.DependencyInjection.Extensions;

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
}
