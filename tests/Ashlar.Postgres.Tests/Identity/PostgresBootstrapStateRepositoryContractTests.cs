using Ashlar.ProviderContractTests.Identity;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Ashlar.Postgres.Tests.Identity;

internal sealed class PostgresBootstrapStateRepositoryContractTests : BootstrapStateRepositoryContractTests
{
    private static readonly SemaphoreSlim ContainerLock = new(1, 1);
    private static readonly Lazy<PostgreSqlContainer> PostgresContainer = new(() => new PostgreSqlBuilder("postgres:15-alpine").Build());
    private static bool _containerStarted;
    private string? _databaseName;

    protected override async Task<IServiceProvider> CreateInitializedServiceProviderAsync()
    {
        await EnsureContainerStartedAsync();

        _databaseName = $"ashlar_contract_{Guid.NewGuid():N}";
        await CreateDatabaseAsync(_databaseName);

        var services = new ServiceCollection();
        services.AddAshlarPostgres(GetConnectionString(_databaseName));
        var provider = services.BuildServiceProvider();
        await provider.InitializeAshlarPostgresSchemaAsync();
        return provider;
    }

    protected override async Task CleanupInitializedServiceProviderAsync()
    {
        if (_databaseName != null)
        {
            await DropDatabaseAsync(_databaseName);
            _databaseName = null;
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

    private static string GetConnectionString(string databaseName)
    {
        var builder = new NpgsqlConnectionStringBuilder(PostgresContainer.Value.GetConnectionString())
        {
            Database = databaseName
        };
        return builder.ConnectionString;
    }

    private static async Task CreateDatabaseAsync(string databaseName)
    {
        await using var connection = await OpenAdminConnectionAsync();
        await using var command = new NpgsqlCommand($"CREATE DATABASE {QuoteIdentifier(databaseName)}", connection);
        await command.ExecuteNonQueryAsync();
    }

    private static async Task DropDatabaseAsync(string databaseName)
    {
        await using var connection = await OpenAdminConnectionAsync();
        await using var command = new NpgsqlCommand($"DROP DATABASE IF EXISTS {QuoteIdentifier(databaseName)} WITH (FORCE)", connection);
        await command.ExecuteNonQueryAsync();
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
