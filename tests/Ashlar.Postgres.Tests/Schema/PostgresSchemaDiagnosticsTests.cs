using Ashlar.Operational.Diagnostics;
using Ashlar.Postgres.Schema;
using Ashlar.Testing;
using Dapper;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using Npgsql;

namespace Ashlar.Postgres.Tests.Schema;

internal sealed class PostgresSchemaDiagnosticsTests : PostgresTestBase
{
    private const string ExpectedMigrationName = "Ashlar.Postgres.Schema.Scripts.0001_Initialize.sql";
    private static readonly DateTimeOffset CheckedAt = new(2026, 5, 20, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public void ConstructorRejectsNullArguments()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new PostgresSchemaDiagnostics(null!, new FakeTimeProvider(CheckedAt)));
            Assert.Throws<ArgumentNullException>(() => _ = new PostgresSchemaDiagnostics(GetDataSource(), null!));
        }
    }

    [Test]
    public async Task CheckAsyncBeforeInitializationReturnsNotInitialized()
    {
        await using (var connection = await GetDataSource().OpenConnectionAsync())
        {
            await connection.ExecuteAsync("DROP TABLE IF EXISTS ashlar_schema_versions;");
        }

        var diagnostics = new PostgresSchemaDiagnostics(GetDataSource(), new FakeTimeProvider(CheckedAt));

        var result = await diagnostics.CheckAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.Unhealthy));
            Assert.That(result.ProviderName, Is.EqualTo("PostgreSQL"));
            Assert.That(result.Reason, Is.EqualTo("Schema has not been initialized."));
            Assert.That(result.CheckedAt, Is.EqualTo(CheckedAt));
            Assert.That(result.SchemaStatus, Is.EqualTo(AshlarSchemaStatus.NotInitialized));
            Assert.That(result.AppliedMigrationCount, Is.Zero);
            Assert.That(result.ExpectedMigrationCount, Is.EqualTo(1));
            Assert.That(result.MissingMigrationCount, Is.EqualTo(1));
            Assert.That(result.LatestAppliedMigrationName, Is.Null);
            Assert.That(result.LatestExpectedMigrationName, Is.EqualTo(ExpectedMigrationName));
            Assert.That(result.MinimumProviderVersion, Is.EqualTo("150000"));
            Assert.That(result.ProviderVersion, Is.Not.Null);
        }
    }

    [Test]
    public async Task CheckAsyncAfterInitializationReturnsCurrent()
    {
        await using var provider = CreateProvider(new FakeTimeProvider(CheckedAt));
        await provider.InitializeAshlarPostgresSchemaAsync();
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
            Assert.That(result.MinimumProviderVersion, Is.EqualTo("150000"));
            Assert.That(result.ProviderVersion, Is.Not.Null);
        }
    }

    [Test]
    public async Task CheckAsyncWithJournalMissingScriptsReturnsPendingMigrations()
    {
        await using var provider = CreateProvider(new FakeTimeProvider(CheckedAt));
        await provider.InitializeAshlarPostgresSchemaAsync();

        await using (var connection = await GetDataSource().OpenConnectionAsync())
        {
            await connection.ExecuteAsync("DELETE FROM ashlar_schema_versions;");
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
        await using var dataSource = new NpgsqlDataSourceBuilder(GetConnectionString()).Build();
        await dataSource.DisposeAsync();
        var logger = new RecordingLogger<PostgresSchemaDiagnostics>();
        var diagnostics = new PostgresSchemaDiagnostics(dataSource, new FakeTimeProvider(CheckedAt), logger);

        var result = await diagnostics.CheckAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.Unknown));
            Assert.That(result.Reason, Is.EqualTo("Schema diagnostics could not query provider state."));
            Assert.That(result.Reason, Does.Not.Contain(GetConnectionString()));
            Assert.That(result.Reason, Does.Not.Contain("SHOW"));
            Assert.That(result.SchemaStatus, Is.EqualTo(AshlarSchemaStatus.Unknown));
            Assert.That(result.CheckedAt, Is.EqualTo(CheckedAt));
            Assert.That(result.ExpectedMigrationCount, Is.EqualTo(1));
            Assert.That(result.ProviderVersion, Is.Null);
            Assert.That(logger.Entries, Has.Count.EqualTo(1));
            Assert.That(logger.Entries[0].Level, Is.EqualTo(LogLevel.Error));
            Assert.That(logger.Entries[0].Message, Is.EqualTo("PostgreSQL schema diagnostics failed."));
            Assert.That(logger.Entries[0].Exception, Is.Not.Null);
        }
    }

    [Test]
    public void CheckAsyncWithCancellationPropagatesCancellation()
    {
        var diagnostics = new PostgresSchemaDiagnostics(GetDataSource(), new FakeTimeProvider(CheckedAt));
        using var cancellationTokenSource = new CancellationTokenSource();
        cancellationTokenSource.Cancel();

        Assert.ThrowsAsync(Is.InstanceOf<OperationCanceledException>(), async () => await diagnostics.CheckAsync(cancellationTokenSource.Token));
    }

    private ServiceProvider CreateProvider(TimeProvider timeProvider)
    {
        var services = new ServiceCollection();
        services.AddSingleton(timeProvider);
        services.AddAshlarPostgres(GetConnectionString());
        return services.BuildServiceProvider();
    }
}
