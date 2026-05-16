using Ashlar.Postgres.Schema;
using Ashlar.Testing;
using Dapper;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Ashlar.Postgres.Tests.Schema;

internal sealed class SchemaManagerTests : PostgresTestBase
{
    private static readonly LogLevel[] ExpectedDbUpLogLevels =
    [
        LogLevel.Trace,
        LogLevel.Debug,
        LogLevel.Information,
        LogLevel.Warning,
        LogLevel.Error,
        LogLevel.Error
    ];

    private static readonly string[] ExpectedDbUpLogMessages =
    [
        "trace 1",
        "debug",
        "info 2",
        "warning 3",
        "error 4",
        "error with exception 5"
    ];

    [Test]
    public void ConstructorNullDataSourceShouldThrow()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new SchemaManager(null!));
    }

    [Test]
    public async Task SchemaManagerWithPostgres14ShouldThrowNotSupported()
    {
        var postgres14 = new PostgreSqlBuilder("postgres:14-alpine").Build();

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

    [Test]
    public void DbUpUpgradeLoggerForwardsAllLevels()
    {
        var logger = new RecordingLogger();
        var upgradeLogger = new SchemaManager.DbUpUpgradeLogger(logger);
        var exception = new InvalidOperationException("upgrade failed");

        upgradeLogger.LogTrace("trace {0}", 1);
        upgradeLogger.LogDebug("debug");
        upgradeLogger.LogInformation("info {0}", 2);
        upgradeLogger.LogWarning("warning {0}", 3);
        upgradeLogger.LogError("error {0}", 4);
        upgradeLogger.LogError(exception, "error with exception {0}", 5);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(logger.Entries.Select(entry => entry.Level), Is.EqualTo(ExpectedDbUpLogLevels));
            Assert.That(logger.Entries.Select(entry => entry.Message), Is.EqualTo(ExpectedDbUpLogMessages));
            Assert.That(logger.Entries.Last().Exception, Is.SameAs(exception));
        }
    }

    [Test]
    public void DbUpUpgradeLoggerRejectsNullLogger()
    {
        Assert.Throws<ArgumentNullException>(() => _ = new SchemaManager.DbUpUpgradeLogger(null!));
    }

    [Test]
    public void DbUpUpgradeLoggerPreservesStructuredStateAndToleratesMalformedFormat()
    {
        var logger = new RecordingLogger();
        var upgradeLogger = new SchemaManager.DbUpUpgradeLogger(logger);

        upgradeLogger.LogInformation("literal { brace {0}", 42);

        var state = (IReadOnlyList<KeyValuePair<string, object?>>)logger.Entries.Single().State!;
        using (Assert.EnterMultipleScope())
        {
            Assert.That(logger.Entries.Single().Message, Is.EqualTo("literal { brace {0}"));
            Assert.That(state[0], Is.EqualTo(new KeyValuePair<string, object?>("Arg0", 42)));
            Assert.That(state[1], Is.EqualTo(new KeyValuePair<string, object?>("{OriginalFormat}", "literal { brace {0}")));
            Assert.Throws<ArgumentOutOfRangeException>(() => _ = state[2]);
            Assert.That(state.ToArray(), Has.Length.EqualTo(2));
            Assert.That(((System.Collections.IEnumerable)state).GetEnumerator().MoveNext(), Is.True);
        }
    }
}
