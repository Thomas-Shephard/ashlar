using Ashlar.Operational.Diagnostics;
using Ashlar.Testing;
using Dapper;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Npgsql;

namespace Ashlar.Postgres.Tests.Messaging;

internal sealed class PostgresEmailOutboxDiagnosticsTests : PostgresTestBase
{
    private static readonly DateTimeOffset CheckedAt = new(2026, 5, 20, 12, 0, 0, TimeSpan.Zero);
    private FakeTimeProvider _timeProvider = null!;
    private ServiceProvider _provider = null!;

    public override async Task OneTimeSetUp()
    {
        await base.OneTimeSetUp();
        _timeProvider = new FakeTimeProvider(CheckedAt);
        var services = new ServiceCollection();
        services.AddSingleton<TimeProvider>(_timeProvider);
        services.AddAshlarPostgres(GetConnectionString());
        services.AddAshlarPostgresEmailOutboxSender(options =>
        {
            options.MaxAttempts = 7;
            options.PollingInterval = TimeSpan.FromSeconds(3);
            options.BatchSize = 11;
        });
        _provider = services.BuildServiceProvider();
        await _provider.InitializeAshlarPostgresSchemaAsync();
    }

    [OneTimeTearDown]
    public async Task DisposeProviderAsync()
    {
        await _provider.DisposeAsync();
    }

    [SetUp]
    public async Task ClearOutboxAsync()
    {
        await EnsureOutboxTableCanBeRecreatedAsync();
        await _provider.InitializeAshlarPostgresSchemaAsync();
        await using var connection = await GetDataSource().OpenConnectionAsync();
        await connection.ExecuteAsync("TRUNCATE ashlar_email_outbox;");
        _timeProvider.SetUtcNow(CheckedAt);
    }

    [Test]
    public void ConstructorRejectsNullArguments()
    {
        var connectionProvider = _provider.GetRequiredService<IPostgresConnectionProvider>();
        var options = Options.Create(new PostgresEmailOutboxOptions());

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new PostgresEmailOutboxDiagnostics(null!, options, _timeProvider));
            Assert.Throws<ArgumentNullException>(() => _ = new PostgresEmailOutboxDiagnostics(connectionProvider, null!, _timeProvider));
            Assert.Throws<ArgumentNullException>(() => _ = new PostgresEmailOutboxDiagnostics(connectionProvider, options, null!));
        }
    }

    [Test]
    public async Task EmptyInitializedOutboxReturnsHealthyZeroCountsAndOptions()
    {
        var result = await _provider.GetRequiredService<IEmailOutboxDiagnostics>().CheckAsync();

        AssertHealthy(result);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.PendingCount, Is.Zero);
            Assert.That(result.ScheduledCount, Is.Zero);
            Assert.That(result.LockedCount, Is.Zero);
            Assert.That(result.ExpiredLockCount, Is.Zero);
            Assert.That(result.FailedCount, Is.Zero);
            Assert.That(result.OldestPendingAt, Is.Null);
            Assert.That(result.OldestFailedAt, Is.Null);
            Assert.That(result.MaxAttempts, Is.EqualTo(7));
            Assert.That(result.PollingInterval, Is.EqualTo(TimeSpan.FromSeconds(3)));
            Assert.That(result.BatchSize, Is.EqualTo(11));
        }
    }

    [Test]
    public async Task CheckAsyncCountsOutboxBucketsAndOldestTimestamps()
    {
        var oldPending = CheckedAt.AddMinutes(-20);
        var newPending = CheckedAt.AddMinutes(-5);
        var scheduled = CheckedAt.AddMinutes(5);
        var lockedUntil = CheckedAt.AddMinutes(10);
        var expiredLock = CheckedAt.AddMinutes(-1);
        var oldestFailed = CheckedAt.AddDays(-2);
        var newestFailed = CheckedAt.AddDays(-1);

        await using (var connection = await GetDataSource().OpenConnectionAsync())
        {
            await connection.ExecuteAsync("""
                INSERT INTO ashlar_email_outbox (id, to_address, subject, text_body, created_at, available_at)
                VALUES (@id1, 'pending-old@example.com', 'Subject', 'Body', @oldPending, @oldPending),
                       (@id2, 'pending-new@example.com', 'Subject', 'Body', @newPending, @newPending),
                       (@id3, 'scheduled@example.com', 'Subject', 'Body', @scheduled, @scheduled);

                INSERT INTO ashlar_email_outbox (id, to_address, subject, text_body, created_at, available_at, locked_until, locked_by)
                VALUES (@id4, 'locked@example.com', 'Subject', 'Body', @oldPending, @oldPending, @lockedUntil, 'worker'),
                       (@id5, 'expired@example.com', 'Subject', 'Body', @oldPending, @oldPending, @expiredLock, 'worker');

                INSERT INTO ashlar_email_outbox (id, to_address, subject, text_body, created_at, available_at, failed_at)
                VALUES (@id6, 'failed-old@example.com', 'Subject', 'Body', @oldPending, @oldPending, @oldestFailed),
                       (@id7, 'failed-new@example.com', 'Subject', 'Body', @oldPending, @oldPending, @newestFailed);
                """, new
            {
                id1 = Guid.NewGuid(),
                id2 = Guid.NewGuid(),
                id3 = Guid.NewGuid(),
                id4 = Guid.NewGuid(),
                id5 = Guid.NewGuid(),
                id6 = Guid.NewGuid(),
                id7 = Guid.NewGuid(),
                oldPending,
                newPending,
                scheduled,
                lockedUntil,
                expiredLock,
                oldestFailed,
                newestFailed
            });
        }

        var result = await _provider.GetRequiredService<IEmailOutboxDiagnostics>().CheckAsync();

        AssertHealthy(result);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.PendingCount, Is.EqualTo(3));
            Assert.That(result.ScheduledCount, Is.EqualTo(1));
            Assert.That(result.LockedCount, Is.EqualTo(1));
            Assert.That(result.ExpiredLockCount, Is.EqualTo(1));
            Assert.That(result.FailedCount, Is.EqualTo(2));
            Assert.That(result.OldestPendingAt, Is.EqualTo(oldPending));
            Assert.That(result.OldestFailedAt, Is.EqualTo(oldestFailed));
        }
    }

    [Test]
    public async Task MissingTableReturnsSafeNotSupportedResult()
    {
        await using (var connection = await GetDataSource().OpenConnectionAsync())
        {
            await connection.ExecuteAsync("DROP TABLE ashlar_email_outbox;");
        }

        var result = await _provider.GetRequiredService<IEmailOutboxDiagnostics>().CheckAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.NotSupported));
            Assert.That(result.ProviderName, Is.EqualTo("Postgres"));
            Assert.That(result.Reason, Is.EqualTo("Email outbox table has not been initialized."));
            Assert.That(result.CheckedAt, Is.EqualTo(CheckedAt));
            Assert.That(result.PendingCount, Is.Null);
            Assert.That(result.MaxAttempts, Is.EqualTo(7));
        }

        await _provider.InitializeAshlarPostgresSchemaAsync();
    }

    [Test]
    public async Task UnexpectedProviderFailureReturnsUnknownSafelyAndLogs()
    {
        await using var dataSource = new NpgsqlDataSourceBuilder(GetConnectionString()).Build();
        await dataSource.DisposeAsync();
        var services = new ServiceCollection();
        services.AddSingleton<TimeProvider>(_timeProvider);
        services.AddSingleton(dataSource);
        services.AddAshlarPostgres(dataSource);
        services.AddAshlarPostgresEmailOutboxSender();
        await using var provider = services.BuildServiceProvider();
        var logger = new RecordingLogger<PostgresEmailOutboxDiagnostics>();
        var diagnostics = new PostgresEmailOutboxDiagnostics(
            provider.GetRequiredService<IPostgresConnectionProvider>(),
            Options.Create(new PostgresEmailOutboxOptions()),
            _timeProvider,
            logger);

        var result = await diagnostics.CheckAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.Unknown));
            Assert.That(result.Reason, Is.EqualTo("Email outbox diagnostics could not query provider state."));
            Assert.That(result.Reason, Does.Not.Contain(GetConnectionString()));
            Assert.That(result.Reason, Does.Not.Contain("ashlar_email_outbox"));
            Assert.That(logger.Entries, Has.Count.EqualTo(1));
            Assert.That(logger.Entries[0].Level, Is.EqualTo(LogLevel.Error));
            Assert.That(logger.Entries[0].Message, Is.EqualTo("PostgreSQL email outbox diagnostics failed."));
            Assert.That(logger.Entries[0].Exception, Is.Not.Null);
        }
    }

    [Test]
    public void CheckAsyncWithCancellationPropagatesCancellation()
    {
        using var cancellationTokenSource = new CancellationTokenSource();
        cancellationTokenSource.Cancel();

        Assert.ThrowsAsync(Is.InstanceOf<OperationCanceledException>(), async () =>
            await _provider.GetRequiredService<IEmailOutboxDiagnostics>().CheckAsync(cancellationTokenSource.Token));
    }

    private static void AssertHealthy(EmailOutboxDiagnosticResult result)
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.Healthy));
            Assert.That(result.ProviderName, Is.EqualTo("Postgres"));
            Assert.That(result.Reason, Is.Null);
            Assert.That(result.CheckedAt, Is.EqualTo(CheckedAt));
        }
    }

    private async Task EnsureOutboxTableCanBeRecreatedAsync()
    {
        await using var connection = await GetDataSource().OpenConnectionAsync();
        var tableCount = await connection.ExecuteScalarAsync<int>("""
            SELECT COUNT(*)
            FROM information_schema.tables
            WHERE table_schema = current_schema()
              AND table_name = 'ashlar_email_outbox';
            """);
        if (tableCount == 0)
        {
            await connection.ExecuteAsync("DROP TABLE IF EXISTS ashlar_schema_versions;");
        }
    }
}
