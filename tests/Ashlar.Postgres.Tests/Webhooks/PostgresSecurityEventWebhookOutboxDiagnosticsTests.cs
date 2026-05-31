using Ashlar.Operational.Diagnostics;
using Ashlar.Testing;
using Dapper;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Npgsql;

namespace Ashlar.Postgres.Tests.Webhooks;

internal sealed class PostgresSecurityEventWebhookOutboxDiagnosticsTests : PostgresTestBase
{
    private static readonly DateTimeOffset CheckedAt = new(2026, 5, 24, 12, 0, 0, TimeSpan.Zero);
    private FakeTimeProvider _timeProvider = null!;
    private ServiceProvider _provider = null!;

    public override async Task OneTimeSetUp()
    {
        await base.OneTimeSetUp();
        _timeProvider = new FakeTimeProvider(CheckedAt);
        var services = new ServiceCollection();
        services.AddSingleton<TimeProvider>(_timeProvider);
        services.AddAshlarPostgres(GetConnectionString());
        services.AddAshlarPostgresSecurityEventWebhookOutbox(options =>
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
        await connection.ExecuteAsync("TRUNCATE ashlar_security_event_webhook_outbox;");
        _timeProvider.SetUtcNow(CheckedAt);
    }

    [Test]
    public void ConstructorRejectsNullArguments()
    {
        var connectionProvider = _provider.GetRequiredService<IPostgresConnectionProvider>();
        var options = Options.Create(new PostgresSecurityEventWebhookOutboxOptions());

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new PostgresSecurityEventWebhookOutboxDiagnostics(null!, options, _timeProvider));
            Assert.Throws<ArgumentNullException>(() => _ = new PostgresSecurityEventWebhookOutboxDiagnostics(connectionProvider, null!, _timeProvider));
            Assert.Throws<ArgumentNullException>(() => _ = new PostgresSecurityEventWebhookOutboxDiagnostics(connectionProvider, options, null!));
        }
    }

    [Test]
    public async Task EmptyInitializedOutboxReturnsHealthyZeroCountsAndOptions()
    {
        var result = await _provider.GetRequiredService<ISecurityEventWebhookOutboxDiagnostics>().CheckAsync();

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
                INSERT INTO ashlar_security_event_webhook_outbox (id, endpoint_name, uri, event_id, event_type, outcome, occurred_at, timeout_ms, body, headers, created_at, available_at)
                VALUES (@id1, 'audit', 'https://example.test/old', @eventId1, 'security.test', 'success', @oldPending, 1000, @body, @headers::jsonb, @oldPending, @oldPending),
                       (@id2, 'audit', 'https://example.test/new', @eventId2, 'security.test', 'success', @newPending, 1000, @body, @headers::jsonb, @newPending, @newPending),
                       (@id3, 'audit', 'https://example.test/scheduled', @eventId3, 'security.test', 'success', @scheduled, 1000, @body, @headers::jsonb, @scheduled, @scheduled);

                INSERT INTO ashlar_security_event_webhook_outbox (id, endpoint_name, uri, event_id, event_type, outcome, occurred_at, timeout_ms, body, headers, created_at, available_at, locked_until, locked_by)
                VALUES (@id4, 'audit', 'https://example.test/locked', @eventId4, 'security.test', 'success', @oldPending, 1000, @body, @headers::jsonb, @oldPending, @oldPending, @lockedUntil, 'worker'),
                       (@id5, 'audit', 'https://example.test/expired', @eventId5, 'security.test', 'success', @oldPending, 1000, @body, @headers::jsonb, @oldPending, @oldPending, @expiredLock, 'worker');

                INSERT INTO ashlar_security_event_webhook_outbox (id, endpoint_name, uri, event_id, event_type, outcome, occurred_at, timeout_ms, body, headers, created_at, available_at, failed_at)
                VALUES (@id6, 'audit', 'https://example.test/failed-old', @eventId6, 'security.test', 'success', @oldPending, 1000, @body, @headers::jsonb, @oldPending, @oldPending, @oldestFailed),
                       (@id7, 'audit', 'https://example.test/failed-new', @eventId7, 'security.test', 'success', @oldPending, 1000, @body, @headers::jsonb, @oldPending, @oldPending, @newestFailed);
                """, new
            {
                id1 = Guid.NewGuid(),
                id2 = Guid.NewGuid(),
                id3 = Guid.NewGuid(),
                id4 = Guid.NewGuid(),
                id5 = Guid.NewGuid(),
                id6 = Guid.NewGuid(),
                id7 = Guid.NewGuid(),
                eventId1 = Guid.NewGuid(),
                eventId2 = Guid.NewGuid(),
                eventId3 = Guid.NewGuid(),
                eventId4 = Guid.NewGuid(),
                eventId5 = Guid.NewGuid(),
                eventId6 = Guid.NewGuid(),
                eventId7 = Guid.NewGuid(),
                body = new byte[] { 1, 2, 3 },
                headers = "{}",
                oldPending,
                newPending,
                scheduled,
                lockedUntil,
                expiredLock,
                oldestFailed,
                newestFailed
            });
        }

        var result = await _provider.GetRequiredService<ISecurityEventWebhookOutboxDiagnostics>().CheckAsync();

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
            await connection.ExecuteAsync("DROP TABLE ashlar_security_event_webhook_outbox;");
        }

        var result = await _provider.GetRequiredService<ISecurityEventWebhookOutboxDiagnostics>().CheckAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.NotSupported));
            Assert.That(result.ProviderName, Is.EqualTo("Postgres"));
            Assert.That(result.Reason, Is.EqualTo("Security event webhook outbox table has not been initialized."));
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
        services.AddAshlarPostgresSecurityEventWebhookOutbox();
        await using var provider = services.BuildServiceProvider();
        var logger = new RecordingLogger<PostgresSecurityEventWebhookOutboxDiagnostics>();
        var diagnostics = new PostgresSecurityEventWebhookOutboxDiagnostics(
            provider.GetRequiredService<IPostgresConnectionProvider>(),
            Options.Create(new PostgresSecurityEventWebhookOutboxOptions()),
            _timeProvider,
            logger);

        var result = await diagnostics.CheckAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.Unknown));
            Assert.That(result.Reason, Is.EqualTo("Security event webhook outbox diagnostics could not query provider state."));
            Assert.That(result.Reason, Does.Not.Contain(GetConnectionString()));
            Assert.That(result.Reason, Does.Not.Contain("ashlar_security_event_webhook_outbox"));
            Assert.That(logger.Entries, Has.Count.EqualTo(1));
            Assert.That(logger.Entries[0].Level, Is.EqualTo(LogLevel.Error));
            Assert.That(logger.Entries[0].Message, Is.EqualTo("PostgreSQL security event webhook outbox diagnostics failed."));
            Assert.That(logger.Entries[0].Exception, Is.Not.Null);
        }
    }

    [Test]
    public void CheckAsyncWithCancellationPropagatesCancellation()
    {
        using var cancellationTokenSource = new CancellationTokenSource();
        cancellationTokenSource.Cancel();

        Assert.ThrowsAsync(Is.InstanceOf<OperationCanceledException>(), async () =>
            await _provider.GetRequiredService<ISecurityEventWebhookOutboxDiagnostics>().CheckAsync(cancellationTokenSource.Token));
    }

    private static void AssertHealthy(SecurityEventWebhookOutboxDiagnosticResult result)
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
              AND table_name = 'ashlar_security_event_webhook_outbox';
            """);
        if (tableCount == 0)
        {
            await connection.ExecuteAsync("DROP TABLE IF EXISTS ashlar_schema_versions;");
        }
    }
}
