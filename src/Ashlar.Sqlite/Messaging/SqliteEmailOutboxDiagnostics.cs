using System.Globalization;
using Ashlar.Operational.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Ashlar.Sqlite.Messaging;

internal sealed class SqliteEmailOutboxDiagnostics(
    ISqliteConnectionProvider connectionProvider,
    IOptions<SqliteEmailOutboxOptions> options,
    TimeProvider timeProvider,
    ILogger<SqliteEmailOutboxDiagnostics>? logger = null) : IEmailOutboxDiagnostics
{
    private const string ProviderName = "Sqlite";
    private static readonly AshlarEmailOutboxDiagnosticsRunner DiagnosticsRunner = new(ProviderName);

    private static readonly Action<ILogger, Exception?> EmailOutboxDiagnosticsFailed =
        LoggerMessage.Define(
            LogLevel.Error,
            new EventId(1004, nameof(EmailOutboxDiagnosticsFailed)),
            "SQLite email outbox diagnostics failed.");

    private readonly ISqliteConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));
    private readonly SqliteEmailOutboxOptions _options = (options ?? throw new ArgumentNullException(nameof(options))).Value;
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    private readonly ILogger<SqliteEmailOutboxDiagnostics> _logger = logger ?? NullLogger<SqliteEmailOutboxDiagnostics>.Instance;

    public async Task<EmailOutboxDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default)
    {
        return await DiagnosticsRunner.CheckAsync(
            _timeProvider,
            _connectionProvider.GetConnectionAsync,
            TableExistsAsync,
            QuerySnapshotAsync,
            _options.MaxAttempts,
            _options.PollingInterval,
            _options.BatchSize,
            LogEmailOutboxDiagnosticsFailed,
            cancellationToken);
    }

    private static async Task<bool> TableExistsAsync(SqliteConnectionHandle connectionHandle, CancellationToken cancellationToken)
    {
        await using var command = connectionHandle.Connection.CreateCommand();
        command.Transaction = connectionHandle.Transaction;
        command.CommandText = """
            SELECT COUNT(*)
            FROM sqlite_master
            WHERE type = 'table'
              AND name = 'ashlar_email_outbox';
            """;
        var result = await command.ExecuteScalarAsync(cancellationToken);
        return Convert.ToInt32(result, CultureInfo.InvariantCulture) > 0;
    }

    private static async Task<EmailOutboxDiagnosticSnapshot> QuerySnapshotAsync(
        SqliteConnectionHandle connectionHandle,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await using var command = connectionHandle.Connection.CreateCommand();
        command.Transaction = connectionHandle.Transaction;
        command.CommandText = """
            SELECT
                COALESCE(SUM(CASE WHEN sent_at IS NULL AND failed_at IS NULL AND available_at <= $now AND (locked_until IS NULL OR locked_until <= $now) THEN 1 ELSE 0 END), 0) AS pending_count,
                COALESCE(SUM(CASE WHEN sent_at IS NULL AND failed_at IS NULL AND available_at > $now THEN 1 ELSE 0 END), 0) AS scheduled_count,
                COALESCE(SUM(CASE WHEN sent_at IS NULL AND failed_at IS NULL AND locked_until > $now THEN 1 ELSE 0 END), 0) AS locked_count,
                COALESCE(SUM(CASE WHEN sent_at IS NULL AND failed_at IS NULL AND locked_until IS NOT NULL AND locked_until <= $now THEN 1 ELSE 0 END), 0) AS expired_lock_count,
                COALESCE(SUM(CASE WHEN failed_at IS NOT NULL THEN 1 ELSE 0 END), 0) AS failed_count,
                MIN(CASE WHEN sent_at IS NULL AND failed_at IS NULL AND available_at <= $now AND (locked_until IS NULL OR locked_until <= $now) THEN available_at END) AS oldest_pending_at,
                MIN(CASE WHEN failed_at IS NOT NULL THEN failed_at END) AS oldest_failed_at
            FROM ashlar_email_outbox;
            """;
        command.AddDateTimeOffsetParameter("$now", now);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        await reader.ReadAsync(cancellationToken);
        return new EmailOutboxDiagnosticSnapshot
        {
            PendingCount = reader.GetInt64(reader.GetOrdinal("pending_count")),
            ScheduledCount = reader.GetInt64(reader.GetOrdinal("scheduled_count")),
            LockedCount = reader.GetInt64(reader.GetOrdinal("locked_count")),
            ExpiredLockCount = reader.GetInt64(reader.GetOrdinal("expired_lock_count")),
            FailedCount = reader.GetInt64(reader.GetOrdinal("failed_count")),
            OldestPendingAt = reader.GetNullableDateTimeOffsetFromText("oldest_pending_at"),
            OldestFailedAt = reader.GetNullableDateTimeOffsetFromText("oldest_failed_at")
        };
    }

    private void LogEmailOutboxDiagnosticsFailed(Exception exception)
    {
        EmailOutboxDiagnosticsFailed(_logger, exception);
    }
}
