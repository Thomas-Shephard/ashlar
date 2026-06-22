using Ashlar.Operational.Diagnostics;
using Ashlar.Sqlite.Schema;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Sqlite.Tests.Schema;

internal sealed class SqliteSchemaDiagnosticsTests : SqliteTestBase
{
    private const string ExpectedMigrationName = "Ashlar.Sqlite.Schema.Scripts.0001_Initialize.sql";
    private static readonly DateTimeOffset CheckedAt = new(2026, 5, 20, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public void ConstructorRejectsNullArguments()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new SqliteSchemaDiagnostics(null!, new FakeTimeProvider(CheckedAt)));
            Assert.Throws<ArgumentNullException>(() => _ = new SqliteSchemaDiagnostics(new SqliteConnectionFactory(GetConnectionString()), null!));
        }
    }

    [Test]
    public async Task CheckAsyncBeforeInitializationReturnsNotInitialized()
    {
        var diagnostics = new SqliteSchemaDiagnostics(new SqliteConnectionFactory(GetConnectionString()), new FakeTimeProvider(CheckedAt));

        var result = await diagnostics.CheckAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.Unhealthy));
            Assert.That(result.ProviderName, Is.EqualTo("SQLite"));
            Assert.That(result.Reason, Is.EqualTo("Schema has not been initialized."));
            Assert.That(result.CheckedAt, Is.EqualTo(CheckedAt));
            Assert.That(result.SchemaStatus, Is.EqualTo(AshlarSchemaStatus.NotInitialized));
            Assert.That(result.AppliedMigrationCount, Is.Zero);
            Assert.That(result.ExpectedMigrationCount, Is.EqualTo(1));
            Assert.That(result.MissingMigrationCount, Is.EqualTo(1));
            Assert.That(result.LatestAppliedMigrationName, Is.Null);
            Assert.That(result.LatestExpectedMigrationName, Is.EqualTo(ExpectedMigrationName));
            Assert.That(result.MinimumProviderVersion, Is.Null);
            Assert.That(result.ProviderVersion, Is.Not.Null);
        }
    }

    [Test]
    public async Task CheckAsyncAfterInitializationReturnsCurrent()
    {
        await using var provider = CreateProvider(new FakeTimeProvider(CheckedAt));
        await provider.InitializeAshlarSqliteSchemaAsync();
        var diagnostics = provider.GetRequiredService<IAshlarSchemaDiagnostics>();

        var result = await diagnostics.CheckAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.Healthy));
            Assert.That(result.Reason, Is.Null);
            Assert.That(result.CheckedAt, Is.EqualTo(CheckedAt));
            Assert.That(result.SchemaStatus, Is.EqualTo(AshlarSchemaStatus.Current));
            Assert.That(result.AppliedMigrationCount, Is.EqualTo(1));
            Assert.That(result.ExpectedMigrationCount, Is.EqualTo(1));
            Assert.That(result.MissingMigrationCount, Is.Zero);
            Assert.That(result.LatestAppliedMigrationName, Is.EqualTo(ExpectedMigrationName));
            Assert.That(result.LatestExpectedMigrationName, Is.EqualTo(ExpectedMigrationName));
            Assert.That(result.MinimumProviderVersion, Is.Null);
            Assert.That(result.ProviderVersion, Is.Not.Null);
        }
    }

    [Test]
    public async Task CheckAsyncWithJournalMissingScriptsReturnsPendingMigrations()
    {
        await using var provider = CreateProvider(new FakeTimeProvider(CheckedAt));
        await provider.InitializeAshlarSqliteSchemaAsync();

        await using (var connection = await OpenConnectionAsync())
        {
            await using var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM ashlar_schema_versions;";
            await command.ExecuteNonQueryAsync();
        }

        var diagnostics = provider.GetRequiredService<IAshlarSchemaDiagnostics>();
        var result = await diagnostics.CheckAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.Unhealthy));
            Assert.That(result.Reason, Is.EqualTo("Schema has pending migrations."));
            Assert.That(result.SchemaStatus, Is.EqualTo(AshlarSchemaStatus.PendingMigrations));
            Assert.That(result.AppliedMigrationCount, Is.Zero);
            Assert.That(result.ExpectedMigrationCount, Is.EqualTo(1));
            Assert.That(result.MissingMigrationCount, Is.EqualTo(1));
            Assert.That(result.LatestAppliedMigrationName, Is.Null);
            Assert.That(result.LatestExpectedMigrationName, Is.EqualTo(ExpectedMigrationName));
        }
    }

    [Test]
    public async Task CheckAsyncWithConnectionFailureReturnsUnknownSafely()
    {
        var databasePath = Path.Combine(GetConnectionString(), "invalid.db");
        var connectionString = new SqliteConnectionStringBuilder { DataSource = databasePath, Pooling = false }.ConnectionString;
        var logger = new RecordingLogger<SqliteSchemaDiagnostics>();
        var diagnostics = new SqliteSchemaDiagnostics(new SqliteConnectionFactory(connectionString), new FakeTimeProvider(CheckedAt), logger);

        var result = await diagnostics.CheckAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.Unknown));
            Assert.That(result.Reason, Is.EqualTo("Schema diagnostics could not query provider state."));
            Assert.That(result.Reason, Does.Not.Contain(databasePath));
            Assert.That(result.Reason, Does.Not.Contain("SELECT"));
            Assert.That(result.SchemaStatus, Is.EqualTo(AshlarSchemaStatus.Unknown));
            Assert.That(result.CheckedAt, Is.EqualTo(CheckedAt));
            Assert.That(result.ExpectedMigrationCount, Is.EqualTo(1));
            Assert.That(result.ProviderVersion, Is.Null);
            Assert.That(logger.Entries, Has.Count.EqualTo(1));
            Assert.That(logger.Entries[0].Level, Is.EqualTo(LogLevel.Error));
            Assert.That(logger.Entries[0].Message, Is.EqualTo("SQLite schema diagnostics failed."));
            Assert.That(logger.Entries[0].Exception, Is.Not.Null);
        }
    }

    [Test]
    public void CheckAsyncWithCancellationPropagatesCancellation()
    {
        var diagnostics = new SqliteSchemaDiagnostics(new SqliteConnectionFactory(GetConnectionString()), new FakeTimeProvider(CheckedAt));
        using var cancellationTokenSource = new CancellationTokenSource();
        cancellationTokenSource.Cancel();

        Assert.ThrowsAsync(Is.InstanceOf<OperationCanceledException>(), async () => await diagnostics.CheckAsync(cancellationTokenSource.Token));
    }

    private ServiceProvider CreateProvider(TimeProvider timeProvider)
    {
        var services = new ServiceCollection();
        services.AddSingleton(timeProvider);
        services.AddAshlarSqlite(GetConnectionString());
        return services.BuildServiceProvider();
    }

    private sealed class RecordingLogger<T> : ILogger<T>
    {
        public List<LogEntry> Entries { get; } = [];

        public IDisposable BeginScope<TState>(TState state) where TState : notnull
        {
            return NullScope.Instance;
        }

        public bool IsEnabled(LogLevel logLevel)
        {
            return true;
        }

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            Entries.Add(new LogEntry(logLevel, formatter(state, exception), exception));
        }

        private sealed class NullScope : IDisposable
        {
            public static readonly NullScope Instance = new();

            public void Dispose()
            {
            }
        }
    }

    private sealed record LogEntry(LogLevel Level, string Message, Exception? Exception);
}
