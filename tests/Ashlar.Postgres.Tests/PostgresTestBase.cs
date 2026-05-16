using Npgsql;
using Testcontainers.PostgreSql;

namespace Ashlar.Postgres.Tests;

internal abstract class PostgresTestBase
{
    private static readonly SemaphoreSlim ContainerLock = new(1, 1);
    private static readonly Lazy<PostgreSqlContainer> PostgresContainer = new(() => new PostgreSqlBuilder("postgres:15-alpine").Build());
    private static bool _containerStarted;
    private static int _databaseSequence;

    private NpgsqlDataSource? _dataSource;
    private string? _connectionString;
    private string? _databaseName;

    [OneTimeSetUp]
    public virtual async Task OneTimeSetUp()
    {
        await EnsureContainerStartedAsync();

        _databaseName = $"ashlar_test_{Interlocked.Increment(ref _databaseSequence)}_{Guid.NewGuid():N}";
        await CreateDatabaseAsync(_databaseName);

        var builder = new NpgsqlConnectionStringBuilder(PostgresContainer.Value.GetConnectionString())
        {
            Database = _databaseName
        };
        _connectionString = builder.ConnectionString;
    }

    [OneTimeTearDown]
    public virtual async Task OneTimeTearDown()
    {
        if (_dataSource != null)
        {
            await _dataSource.DisposeAsync();
        }

        if (_databaseName != null)
        {
            await DropDatabaseAsync(_databaseName);
        }
    }

    protected string GetConnectionString()
    {
        return _connectionString ?? throw new InvalidOperationException("PostgreSQL test database has not been initialized.");
    }

    protected NpgsqlDataSource GetDataSource()
    {
        return _dataSource ??= new NpgsqlDataSourceBuilder(GetConnectionString()).Build();
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

    private static async Task CreateDatabaseAsync(string databaseName)
    {
        await using var connection = await OpenAdminConnectionAsync();
        await using var command = new NpgsqlCommand($"CREATE DATABASE {QuoteIdentifier(databaseName)}", connection);
        await command.ExecuteNonQueryAsync();
    }

    private static async Task DropDatabaseAsync(string databaseName)
    {
        await using var connection = await OpenAdminConnectionAsync();
        await using var command = new NpgsqlCommand(
            $"DROP DATABASE IF EXISTS {QuoteIdentifier(databaseName)} WITH (FORCE)",
            connection);
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
