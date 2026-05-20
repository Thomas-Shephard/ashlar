using Npgsql;
using Testcontainers.PostgreSql;
using Microsoft.Extensions.DependencyInjection;

namespace Ashlar.Postgres.Tests.Identity;

internal static class PostgresContractDatabase
{
    private static readonly SemaphoreSlim ContainerLock = new(1, 1);
    private static readonly Lazy<PostgreSqlContainer> PostgresContainer = new(() => new PostgreSqlBuilder("postgres:15-alpine").Build());
    private static bool _containerStarted;

    public static Task<PostgresContractDatabaseLease> CreateInitializedServiceProviderAsync()
    {
        return CreateInitializedServiceProviderAsync(_ => { });
    }

    public static async Task<PostgresContractDatabaseLease> CreateInitializedServiceProviderAsync(Action<IServiceCollection> configureServices)
    {
        var databaseName = await CreateDatabaseAsync();
        var services = new ServiceCollection();
        services.AddAshlarPostgres(GetConnectionString(databaseName));
        services.AddAshlarPostgresAuditSink();
        configureServices(services);
        var provider = services.BuildServiceProvider();
        await provider.InitializeAshlarPostgresSchemaAsync();
        return new PostgresContractDatabaseLease(databaseName, provider);
    }

    public static async Task<string> CreateDatabaseAsync()
    {
        await EnsureContainerStartedAsync();

        var databaseName = $"ashlar_contract_{Guid.NewGuid():N}";
        await using var connection = await OpenAdminConnectionAsync();
        await using var command = new NpgsqlCommand($"CREATE DATABASE {QuoteIdentifier(databaseName)}", connection);
        await command.ExecuteNonQueryAsync();
        return databaseName;
    }

    public static string GetConnectionString(string databaseName)
    {
        var builder = new NpgsqlConnectionStringBuilder(PostgresContainer.Value.GetConnectionString())
        {
            Database = databaseName
        };
        return builder.ConnectionString;
    }

    public static async Task DropDatabaseAsync(string databaseName)
    {
        await using var connection = await OpenAdminConnectionAsync();
        await using var command = new NpgsqlCommand($"DROP DATABASE IF EXISTS {QuoteIdentifier(databaseName)} WITH (FORCE)", connection);
        await command.ExecuteNonQueryAsync();
    }

    public static async Task DisposeContainerAsync()
    {
        if (!_containerStarted)
        {
            return;
        }

        await ContainerLock.WaitAsync();
        try
        {
            if (_containerStarted)
            {
                await PostgresContainer.Value.StopAsync();
                await PostgresContainer.Value.DisposeAsync();
                _containerStarted = false;
            }
        }
        finally
        {
            ContainerLock.Release();
        }
    }

    private static async Task EnsureContainerStartedAsync()
    {
        if (_containerStarted)
        {
            return;
        }

        await ContainerLock.WaitAsync();
        try
        {
            if (!_containerStarted)
            {
                await PostgresContainer.Value.StartAsync();
                _containerStarted = true;
            }
        }
        finally
        {
            ContainerLock.Release();
        }
    }

    private static async Task<NpgsqlConnection> OpenAdminConnectionAsync()
    {
        var builder = new NpgsqlConnectionStringBuilder(PostgresContainer.Value.GetConnectionString())
        {
            Database = "postgres"
        };

        var connection = new NpgsqlConnection(builder.ConnectionString);
        await connection.OpenAsync();
        return connection;
    }

    private static string QuoteIdentifier(string identifier)
    {
        return "\"" + identifier.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }
}

internal sealed class PostgresContractDatabaseLease(string databaseName, IServiceProvider serviceProvider)
{
    public IServiceProvider ServiceProvider { get; } = serviceProvider;

    public string ConnectionString => PostgresContractDatabase.GetConnectionString(databaseName);

    public Task DropDatabaseAsync()
    {
        return PostgresContractDatabase.DropDatabaseAsync(databaseName);
    }
}
