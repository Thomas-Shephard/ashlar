using Ashlar.Identity.Abstractions;
using Ashlar.Postgres;
using Ashlar.Postgres.Schema;
using Microsoft.Extensions.DependencyInjection.Extensions;
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
        services.TryAddScoped<IIdentityRepository, PostgresIdentityRepository>();
        services.TryAddTransient<SchemaManager>();

        return services;
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
        services.TryAddScoped<IIdentityRepository, PostgresIdentityRepository>();
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
}
