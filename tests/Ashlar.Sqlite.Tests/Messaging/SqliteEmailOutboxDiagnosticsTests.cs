using Ashlar.Operational.Diagnostics;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Sqlite.Tests.Messaging;

internal sealed class SqliteEmailOutboxDiagnosticsTests : SqliteTestBase
{
    private static readonly DateTimeOffset CheckedAt = new(2026, 5, 20, 12, 0, 0, TimeSpan.Zero);
    private FakeTimeProvider _timeProvider = null!;
    private ServiceProvider _provider = null!;

    [SetUp]
    public async Task SetUpAsync()
    {
        _timeProvider = new FakeTimeProvider(CheckedAt);
        var services = new ServiceCollection();
        services.AddSingleton<TimeProvider>(_timeProvider);
        services.AddAshlarSqlite(GetConnectionString());
        services.AddAshlarSqliteEmailOutboxSender(options =>
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
        var options = Options.Create(new SqliteEmailOutboxOptions());

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new SqliteEmailOutboxDiagnostics(null!, options, _timeProvider));
            Assert.Throws<ArgumentNullException>(() => _ = new SqliteEmailOutboxDiagnostics(connectionProvider, null!, _timeProvider));
            Assert.Throws<ArgumentNullException>(() => _ = new SqliteEmailOutboxDiagnostics(connectionProvider, options, null!));
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

        await ExecuteAsync("""
            INSERT INTO ashlar_email_outbox (id, to_address, subject, text_body, sensitivity, body_protection, headers, metadata, created_at, available_at)
            VALUES ($id1, 'pending-old@example.com', 'Subject', 'live-token-link', 'ContainsLiveSecret', 'SecretProtector', '{"X-Token":"secret-header"}', '{"token_hash":"secret-hash"}', $oldPending, $oldPending),
                   ($id2, 'pending-new@example.com', 'Subject', 'Body', 'Normal', 'None', '{}', '{}', $newPending, $newPending),
                   ($id3, 'scheduled@example.com', 'Subject', 'secret-scheduled', 'ContainsLiveSecret', 'SecretProtector', '{}', '{}', $scheduled, $scheduled);

            INSERT INTO ashlar_email_outbox (id, to_address, subject, text_body, sensitivity, body_protection, created_at, available_at, locked_until, locked_by)
            VALUES ($id4, 'locked@example.com', 'Subject', 'secret-locked', 'ContainsLiveSecret', 'SecretProtector', $oldPending, $oldPending, $lockedUntil, 'worker'),
                   ($id5, 'expired@example.com', 'Subject', 'Body', 'Normal', 'None', $oldPending, $oldPending, $expiredLock, 'worker');

            INSERT INTO ashlar_email_outbox (id, to_address, subject, text_body, sensitivity, body_protection, created_at, available_at, failed_at)
            VALUES ($id6, 'failed-old@example.com', 'Subject', 'secret-failed', 'ContainsLiveSecret', 'SecretProtector', $oldPending, $oldPending, $oldestFailed),
                   ($id7, 'failed-new@example.com', 'Subject', 'Body', 'Normal', 'None', $oldPending, $oldPending, $newestFailed);
            """, command =>
        {
            command.AddGuidParameter("$id1", Guid.NewGuid());
            command.AddGuidParameter("$id2", Guid.NewGuid());
            command.AddGuidParameter("$id3", Guid.NewGuid());
            command.AddGuidParameter("$id4", Guid.NewGuid());
            command.AddGuidParameter("$id5", Guid.NewGuid());
            command.AddGuidParameter("$id6", Guid.NewGuid());
            command.AddGuidParameter("$id7", Guid.NewGuid());
            command.AddDateTimeOffsetParameter("$oldPending", oldPending);
            command.AddDateTimeOffsetParameter("$newPending", newPending);
            command.AddDateTimeOffsetParameter("$scheduled", scheduled);
            command.AddDateTimeOffsetParameter("$lockedUntil", lockedUntil);
            command.AddDateTimeOffsetParameter("$expiredLock", expiredLock);
            command.AddDateTimeOffsetParameter("$oldestFailed", oldestFailed);
            command.AddDateTimeOffsetParameter("$newestFailed", newestFailed);
        });

        var result = await _provider.GetRequiredService<IEmailOutboxDiagnostics>().CheckAsync();

        AssertHealthy(result);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.PendingCount, Is.EqualTo(3));
            Assert.That(result.ScheduledCount, Is.EqualTo(1));
            Assert.That(result.LockedCount, Is.EqualTo(1));
            Assert.That(result.ExpiredLockCount, Is.EqualTo(1));
            Assert.That(result.FailedCount, Is.EqualTo(2));
            Assert.That(result.SensitivePendingCount, Is.EqualTo(1));
            Assert.That(result.SensitiveScheduledCount, Is.EqualTo(1));
            Assert.That(result.SensitiveLockedCount, Is.EqualTo(1));
            Assert.That(result.SensitiveFailedCount, Is.EqualTo(1));
            Assert.That(result.OldestPendingAt, Is.EqualTo(oldPending));
            Assert.That(result.OldestFailedAt, Is.EqualTo(oldestFailed));
            Assert.That(result.ToString(), Does.Not.Contain("live-token-link"));
            Assert.That(result.ToString(), Does.Not.Contain("secret-header"));
            Assert.That(result.ToString(), Does.Not.Contain("secret-hash"));
        }
    }

    [Test]
    public async Task MissingTableReturnsSafeNotSupportedResult()
    {
        await ExecuteAsync("DROP TABLE ashlar_email_outbox;", _ => { });

        var result = await _provider.GetRequiredService<IEmailOutboxDiagnostics>().CheckAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.NotSupported));
            Assert.That(result.ProviderName, Is.EqualTo("Sqlite"));
            Assert.That(result.Reason, Is.EqualTo("Email outbox table has not been initialized."));
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
        services.AddAshlarSqliteEmailOutboxSender();
        await using var provider = services.BuildServiceProvider();
        var logger = new RecordingLogger<SqliteEmailOutboxDiagnostics>();
        var diagnostics = new SqliteEmailOutboxDiagnostics(
            provider.GetRequiredService<ISqliteConnectionProvider>(),
            Options.Create(new SqliteEmailOutboxOptions()),
            _timeProvider,
            logger);

        var result = await diagnostics.CheckAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.Unknown));
            Assert.That(result.Reason, Is.EqualTo("Email outbox diagnostics could not query provider state."));
            Assert.That(result.Reason, Does.Not.Contain(databasePath));
            Assert.That(result.Reason, Does.Not.Contain("ashlar_email_outbox"));
            Assert.That(logger.Entries, Has.Count.EqualTo(1));
            Assert.That(logger.Entries[0].Level, Is.EqualTo(LogLevel.Error));
            Assert.That(logger.Entries[0].Message, Is.EqualTo("SQLite email outbox diagnostics failed."));
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

    private async Task ExecuteAsync(string sql, Action<SqliteCommand> bind)
    {
        await using var connection = await OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        bind(command);
        await command.ExecuteNonQueryAsync();
    }

    private static void AssertHealthy(EmailOutboxDiagnosticResult result)
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.Healthy));
            Assert.That(result.ProviderName, Is.EqualTo("Sqlite"));
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
