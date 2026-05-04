using Ashlar.Postgres.Schema;
using Dapper;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Ashlar.Postgres.Tests.Schema;

public sealed class SchemaManagerTests : PostgresTestBase
{
    [Test]
    public void ConstructorNullDataSourceShouldThrow()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new SchemaManager(null!));
    }

    [Test]
    public async Task SchemaManagerWithPostgres14ShouldThrowNotSupported()
    {
        var postgres14 = new PostgreSqlBuilder()
            .WithImage("postgres:14-alpine")
            .Build();

        await postgres14.StartAsync();
        try
        {
            await using var dataSource = new NpgsqlDataSourceBuilder(postgres14.GetConnectionString()).Build();
            var schemaManager = new SchemaManager(dataSource);
            Assert.ThrowsAsync<NotSupportedException>(async () => await schemaManager.InitializeAsync());
        }
        finally
        {
            await postgres14.DisposeAsync();
        }
    }

    [Test]
    public void SchemaManagerWithNullVersionStringShouldThrow()
    {
        var mockSchemaManager = new MockSchemaManager(GetDataSource(), null);
        Assert.ThrowsAsync<InvalidOperationException>(async () => await mockSchemaManager.InitializeAsync());
    }

    [Test]
    public void SchemaManagerWithInvalidVersionStringShouldThrow()
    {
        var mockSchemaManager = new MockSchemaManager(GetDataSource(), "not-a-number");
        Assert.ThrowsAsync<InvalidOperationException>(async () => await mockSchemaManager.InitializeAsync());
    }

    private sealed class MockSchemaManager(NpgsqlDataSource dataSource, string? versionToReturn) : SchemaManager(dataSource)
    {
        protected override Task<string?> GetServerVersionAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
        {
            return Task.FromResult(versionToReturn);
        }
    }

    [Test]
    public async Task SchemaManagerFailsUpgradeShouldThrow()
    {
        var dataSource = GetDataSource();
        var username = $"ashlar_restricted_{Guid.NewGuid():N}";

        // Create a restricted user that cannot create tables
        await using (var connection = await dataSource.OpenConnectionAsync())
        {
            await using var cmd = new NpgsqlCommand($"CREATE USER {username} WITH PASSWORD 'pass'; GRANT CONNECT ON DATABASE postgres TO {username};", connection);
            await cmd.ExecuteNonQueryAsync();
        }

        var builder = new NpgsqlConnectionStringBuilder(GetConnectionString())
        {
            Username = username,
            Password = "pass"
        };

        await using var restrictedDataSource = new NpgsqlDataSourceBuilder(builder.ConnectionString).Build();
        var schemaManager = new SchemaManager(restrictedDataSource);

        // This should fail during PerformUpgrade because it can't create the journal table
        Assert.ThrowsAsync<InvalidOperationException>(async () => await schemaManager.InitializeAsync());
    }

    [Test]
    public async Task InitializeAsyncCreatesSecurityEventsTable()
    {
        var services = new ServiceCollection();
        services.AddAshlarPostgres(GetConnectionString());
        await using var provider = services.BuildServiceProvider();

        await provider.InitializeAshlarPostgresSchemaAsync();

        await using var connection = await GetDataSource().OpenConnectionAsync();
        var exists = await connection.ExecuteScalarAsync<bool>(
            "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'ashlar_security_events');"
        );
        Assert.That(exists, Is.True);
    }
}
