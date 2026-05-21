using Ashlar.Operational.Diagnostics;
using Dapper;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Ashlar.Postgres.Messaging;

internal sealed class PostgresEmailOutboxDiagnostics(
    IPostgresConnectionProvider connectionProvider,
    IOptions<PostgresEmailOutboxOptions> options,
    TimeProvider timeProvider,
    ILogger<PostgresEmailOutboxDiagnostics>? logger = null) : IEmailOutboxDiagnostics
{
    private const string ProviderName = "Postgres";
    private const string MissingTableReason = "Email outbox table has not been initialized.";
    private const string QueryFailedReason = "Email outbox diagnostics could not query provider state.";

    private static readonly Action<ILogger, Exception?> EmailOutboxDiagnosticsFailed =
        LoggerMessage.Define(
            LogLevel.Error,
            new EventId(1006, nameof(EmailOutboxDiagnosticsFailed)),
            "PostgreSQL email outbox diagnostics failed.");

    private readonly IPostgresConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));
    private readonly PostgresEmailOutboxOptions _options = (options ?? throw new ArgumentNullException(nameof(options))).Value;
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    private readonly ILogger<PostgresEmailOutboxDiagnostics> _logger = logger ?? NullLogger<PostgresEmailOutboxDiagnostics>.Instance;

    public async Task<EmailOutboxDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default)
    {
        var checkedAt = _timeProvider.GetUtcNow();

        try
        {
            EmailOutboxDiagnosticResult result;
            await using (var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken))
            {
                var tableExists = await TableExistsAsync(connectionHandle, cancellationToken);
                if (!tableExists)
                {
                    result = CreateResult(AshlarDiagnosticStatus.NotSupported, MissingTableReason, checkedAt);
                }
                else
                {
                    var snapshot = await QuerySnapshotAsync(connectionHandle, checkedAt, cancellationToken);
                    result = CreateResult(AshlarDiagnosticStatus.Healthy, null, checkedAt, snapshot);
                }
            }

            return result;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            EmailOutboxDiagnosticsFailed(_logger, ex);
            return CreateResult(AshlarDiagnosticStatus.Unknown, QueryFailedReason, checkedAt);
        }
    }

    private static async Task<bool> TableExistsAsync(PostgresConnectionHandle connectionHandle, CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT COUNT(*)
            FROM information_schema.tables
            WHERE table_schema = current_schema()
              AND table_name = 'ashlar_email_outbox';
            """;
        var command = new CommandDefinition(sql, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
        var count = await connectionHandle.Connection.ExecuteScalarAsync<int>(command);
        return count > 0;
    }

    private static async Task<EmailOutboxSnapshot> QuerySnapshotAsync(
        PostgresConnectionHandle connectionHandle,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT
                COUNT(*) FILTER (
                    WHERE sent_at IS NULL
                      AND failed_at IS NULL
                      AND available_at <= @Now
                      AND (locked_until IS NULL OR locked_until <= @Now)
                ) AS PendingCount,
                COUNT(*) FILTER (
                    WHERE sent_at IS NULL
                      AND failed_at IS NULL
                      AND available_at > @Now
                ) AS ScheduledCount,
                COUNT(*) FILTER (
                    WHERE sent_at IS NULL
                      AND failed_at IS NULL
                      AND locked_until > @Now
                ) AS LockedCount,
                COUNT(*) FILTER (
                    WHERE sent_at IS NULL
                      AND failed_at IS NULL
                      AND locked_until IS NOT NULL
                      AND locked_until <= @Now
                ) AS ExpiredLockCount,
                COUNT(*) FILTER (
                    WHERE failed_at IS NOT NULL
                ) AS FailedCount,
                MIN(available_at) FILTER (
                    WHERE sent_at IS NULL
                      AND failed_at IS NULL
                      AND available_at <= @Now
                      AND (locked_until IS NULL OR locked_until <= @Now)
                ) AS OldestPendingAt,
                MIN(failed_at) FILTER (
                    WHERE failed_at IS NOT NULL
                ) AS OldestFailedAt
            FROM ashlar_email_outbox;
            """;
        var command = new CommandDefinition(sql, new { Now = now }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
        return await connectionHandle.Connection.QuerySingleAsync<EmailOutboxSnapshot>(command);
    }

    private EmailOutboxDiagnosticResult CreateResult(
        AshlarDiagnosticStatus status,
        string? reason,
        DateTimeOffset checkedAt,
        EmailOutboxSnapshot? snapshot = null)
    {
        return new EmailOutboxDiagnosticResult(
            status,
            ProviderName,
            reason,
            checkedAt,
            snapshot?.PendingCount,
            snapshot?.ScheduledCount,
            snapshot?.LockedCount,
            snapshot?.ExpiredLockCount,
            snapshot?.FailedCount,
            snapshot?.OldestPendingAt,
            snapshot?.OldestFailedAt,
            _options.MaxAttempts,
            _options.PollingInterval,
            _options.BatchSize);
    }

    private sealed class EmailOutboxSnapshot
    {
        public long PendingCount { get; init; }
        public long ScheduledCount { get; init; }
        public long LockedCount { get; init; }
        public long ExpiredLockCount { get; init; }
        public long FailedCount { get; init; }
        public DateTimeOffset? OldestPendingAt { get; init; }
        public DateTimeOffset? OldestFailedAt { get; init; }
    }
}
