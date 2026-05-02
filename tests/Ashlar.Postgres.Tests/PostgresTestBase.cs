using Npgsql;
using Testcontainers.PostgreSql;

namespace Ashlar.Postgres.Tests;

public abstract class PostgresTestBase
{
    private PostgreSqlContainer PostgresContainer { get; } = new PostgreSqlBuilder().WithImage("postgres:15-alpine").Build();

    private NpgsqlDataSource? _dataSource;

    [OneTimeSetUp]
    public virtual async Task OneTimeSetUp()
    {
        await PostgresContainer.StartAsync();
    }

    [OneTimeTearDown]
    public virtual async Task OneTimeTearDown()
    {
        if (_dataSource != null)
        {
            await _dataSource.DisposeAsync();
        }

        await PostgresContainer.DisposeAsync();
    }

    protected string GetConnectionString() => PostgresContainer.GetConnectionString();

    protected NpgsqlDataSource GetDataSource()
    {
        return _dataSource ??= new NpgsqlDataSourceBuilder(GetConnectionString()).Build();
    }
}
