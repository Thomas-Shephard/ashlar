using Ashlar.Operational.Diagnostics;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Sqlite.Tests.Webhooks;

internal sealed class SqliteSecurityEventWebhookOutboxDiagnosticsTests : SqliteTestBase
{
    private static readonly DateTimeOffset CheckedAt = new(2026, 5, 24, 12, 0, 0, TimeSpan.Zero);
    private FakeTimeProvider _timeProvider = null!;
    private ServiceProvider _provider = null!;

    [SetUp]
    public async Task SetUpAsync()
    {
        _timeProvider = new FakeTimeProvider(CheckedAt);
        var services = new ServiceCollection();
        services.AddSingleton<TimeProvider>(_timeProvider);
        services.AddAshlarSqlite(GetConnectionString());
        services.AddAshlarSqliteSecurityEventWebhookOutbox(options =>
        {
            options.MaxAttempts = 7;
            options.PollingInterval = TimeSpan.FromSeconds(3);
            options.BatchSize = 11;
        });
        _provider = services.BuildServiceProvider();
        await _provider.InitializeAshlarSqliteSchemaAsync();
    }

    [TearDown]
    public async Task TearDownAsync()
    {
        await _provider.DisposeAsync();
    }

    [Test]
    public void ConstructorRejectsNullArguments()
    {
        var connectionProvider = _provider.GetRequiredService<ISqliteConnectionProvider>();
        var options = Options.Create(new SqliteSecurityEventWebhookOutboxOptions());

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new SqliteSecurityEventWebhookOutboxDiagnostics(null!, options, _timeProvider));
            Assert.Throws<ArgumentNullException>(() => _ = new SqliteSecurityEventWebhookOutboxDiagnostics(connectionProvider, null!, _timeProvider));
            Assert.Throws<ArgumentNullException>(() => _ = new SqliteSecurityEventWebhookOutboxDiagnostics(connectionProvider, options, null!));
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
        var discardedFailed = CheckedAt.AddDays(-3);
        var oldestFailed = CheckedAt.AddDays(-2);
        var newestFailed = CheckedAt.AddDays(-1);

        await ExecuteAsync("""
            INSERT INTO ashlar_security_event_webhook_outbox (id, endpoint_name, uri, event_id, event_type, outcome, occurred_at, timeout_ms, body, headers, created_at, available_at)
            VALUES ($id1, 'audit', 'https://example.test/old', $eventId1, 'security.test', 'success', $oldPending, 1000, $body, $headers, $oldPending, $oldPending),
                   ($id2, 'audit', 'https://example.test/new', $eventId2, 'security.test', 'success', $newPending, 1000, $body, $headers, $newPending, $newPending),
                   ($id3, 'audit', 'https://example.test/scheduled', $eventId3, 'security.test', 'success', $scheduled, 1000, $body, $headers, $scheduled, $scheduled);

            INSERT INTO ashlar_security_event_webhook_outbox (id, endpoint_name, uri, event_id, event_type, outcome, occurred_at, timeout_ms, body, headers, created_at, available_at, locked_until, locked_by)
            VALUES ($id4, 'audit', 'https://example.test/locked', $eventId4, 'security.test', 'success', $oldPending, 1000, $body, $headers, $oldPending, $oldPending, $lockedUntil, 'worker'),
                   ($id5, 'audit', 'https://example.test/expired', $eventId5, 'security.test', 'success', $oldPending, 1000, $body, $headers, $oldPending, $oldPending, $expiredLock, 'worker');

            INSERT INTO ashlar_security_event_webhook_outbox (id, endpoint_name, uri, event_id, event_type, outcome, occurred_at, timeout_ms, body, headers, created_at, available_at, failed_at)
            VALUES ($id6, 'audit', 'https://example.test/failed-old', $eventId6, 'security.test', 'success', $oldPending, 1000, $body, $headers, $oldPending, $oldPending, $oldestFailed),
                   ($id7, 'audit', 'https://example.test/failed-new', $eventId7, 'security.test', 'success', $oldPending, 1000, $body, $headers, $oldPending, $oldPending, $newestFailed);

            INSERT INTO ashlar_security_event_webhook_outbox (id, endpoint_name, uri, event_id, event_type, outcome, occurred_at, timeout_ms, body, headers, created_at, available_at, failed_at, discarded_at)
            VALUES ($id8, 'audit', 'https://example.test/discarded', $eventId8, 'security.test', 'success', $oldPending, 1000, $body, $headers, $oldPending, $oldPending, $discardedFailed, $checkedAt);
            """, command =>
        {
            command.AddGuidParameter("$id1", Guid.NewGuid());
            command.AddGuidParameter("$id2", Guid.NewGuid());
            command.AddGuidParameter("$id3", Guid.NewGuid());
            command.AddGuidParameter("$id4", Guid.NewGuid());
            command.AddGuidParameter("$id5", Guid.NewGuid());
            command.AddGuidParameter("$id6", Guid.NewGuid());
            command.AddGuidParameter("$id7", Guid.NewGuid());
            command.AddGuidParameter("$id8", Guid.NewGuid());
            command.AddGuidParameter("$eventId1", Guid.NewGuid());
            command.AddGuidParameter("$eventId2", Guid.NewGuid());
            command.AddGuidParameter("$eventId3", Guid.NewGuid());
            command.AddGuidParameter("$eventId4", Guid.NewGuid());
            command.AddGuidParameter("$eventId5", Guid.NewGuid());
            command.AddGuidParameter("$eventId6", Guid.NewGuid());
            command.AddGuidParameter("$eventId7", Guid.NewGuid());
            command.AddGuidParameter("$eventId8", Guid.NewGuid());
            command.AddParameter("$body", new byte[] { 1, 2, 3 });
            command.AddParameter("$headers", "{}");
            command.AddDateTimeOffsetParameter("$oldPending", oldPending);
            command.AddDateTimeOffsetParameter("$newPending", newPending);
            command.AddDateTimeOffsetParameter("$scheduled", scheduled);
            command.AddDateTimeOffsetParameter("$lockedUntil", lockedUntil);
            command.AddDateTimeOffsetParameter("$expiredLock", expiredLock);
            command.AddDateTimeOffsetParameter("$discardedFailed", discardedFailed);
            command.AddDateTimeOffsetParameter("$oldestFailed", oldestFailed);
            command.AddDateTimeOffsetParameter("$newestFailed", newestFailed);
            command.AddDateTimeOffsetParameter("$checkedAt", CheckedAt);
        });

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
        await ExecuteAsync("DROP TABLE ashlar_security_event_webhook_outbox;", _ => { });

        var result = await _provider.GetRequiredService<ISecurityEventWebhookOutboxDiagnostics>().CheckAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.NotSupported));
            Assert.That(result.ProviderName, Is.EqualTo("SQLite"));
            Assert.That(result.Reason, Is.EqualTo("Security event webhook outbox table has not been initialized."));
            Assert.That(result.CheckedAt, Is.EqualTo(CheckedAt));
            Assert.That(result.PendingCount, Is.Null);
            Assert.That(result.MaxAttempts, Is.EqualTo(7));
        }
    }

    [Test]
    public async Task UnexpectedProviderFailureReturnsUnknownSafelyAndLogs()
    {
        var baseConnectionString = new SqliteConnectionStringBuilder(GetConnectionString());
        var databasePath = Path.Combine(Path.GetDirectoryName(baseConnectionString.DataSource)!, $"missing-{Guid.NewGuid():N}.db");
        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false
        }.ConnectionString;
        var services = new ServiceCollection();
        services.AddAshlarSqlite(connectionString);
        services.AddAshlarSqliteSecurityEventWebhookOutbox();
        await using var provider = services.BuildServiceProvider();
        var logger = new RecordingLogger<SqliteSecurityEventWebhookOutboxDiagnostics>();
        var diagnostics = new SqliteSecurityEventWebhookOutboxDiagnostics(
            provider.GetRequiredService<ISqliteConnectionProvider>(),
            Options.Create(new SqliteSecurityEventWebhookOutboxOptions()),
            _timeProvider,
            logger);

        var result = await diagnostics.CheckAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.Unknown));
            Assert.That(result.Reason, Is.EqualTo("Security event webhook outbox diagnostics could not query provider state."));
            Assert.That(result.Reason, Does.Not.Contain(databasePath));
            Assert.That(result.Reason, Does.Not.Contain("ashlar_security_event_webhook_outbox"));
            Assert.That(logger.Entries, Has.Count.EqualTo(1));
            Assert.That(logger.Entries[0].Level, Is.EqualTo(LogLevel.Error));
            Assert.That(logger.Entries[0].Message, Is.EqualTo("SQLite security event webhook outbox diagnostics failed."));
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

    private async Task ExecuteAsync(string sql, Action<SqliteCommand> bind)
    {
        await using var connection = await OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        bind(command);
        await command.ExecuteNonQueryAsync();
    }

    private static void AssertHealthy(SecurityEventWebhookOutboxDiagnosticResult result)
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.Healthy));
            Assert.That(result.ProviderName, Is.EqualTo("SQLite"));
            Assert.That(result.Reason, Is.Null);
            Assert.That(result.CheckedAt, Is.EqualTo(CheckedAt));
        }
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
