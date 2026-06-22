using Ashlar.Operational.Diagnostics;
using Dapper;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Ashlar.Postgres.Webhooks;

internal sealed class PostgresSecurityEventWebhookOutboxDiagnostics(
    IPostgresConnectionProvider connectionProvider,
    IOptions<PostgresSecurityEventWebhookOutboxOptions> options,
    TimeProvider timeProvider,
    ILogger<PostgresSecurityEventWebhookOutboxDiagnostics>? logger = null) : ISecurityEventWebhookOutboxDiagnostics
{
    private const string ProviderName = "PostgreSQL";
    private static readonly SecurityEventWebhookOutboxDiagnosticsRunner DiagnosticsRunner = new(ProviderName);

    private static readonly Action<ILogger, Exception?> WebhookOutboxDiagnosticsFailed =
        LoggerMessage.Define(
            LogLevel.Error,
            new EventId(1008, nameof(WebhookOutboxDiagnosticsFailed)),
            "PostgreSQL security event webhook outbox diagnostics failed.");

    private readonly IPostgresConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));
    private readonly PostgresSecurityEventWebhookOutboxOptions _options = (options ?? throw new ArgumentNullException(nameof(options))).Value;
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    private readonly ILogger<PostgresSecurityEventWebhookOutboxDiagnostics> _logger = logger ?? NullLogger<PostgresSecurityEventWebhookOutboxDiagnostics>.Instance;

    public async Task<SecurityEventWebhookOutboxDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default)
    {
        return await DiagnosticsRunner.CheckAsync(
            _timeProvider,
            new SecurityEventWebhookOutboxDiagnosticsContext<PostgresConnectionHandle>(
                _connectionProvider.GetConnectionAsync,
                TableExistsAsync,
                QuerySnapshotAsync,
                LogWebhookOutboxDiagnosticsFailed),
            new SecurityEventWebhookOutboxDiagnosticOptions(_options.MaxAttempts, _options.PollingInterval, _options.BatchSize),
            cancellationToken);
    }

    private static async Task<bool> TableExistsAsync(PostgresConnectionHandle connectionHandle, CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT COUNT(*)
            FROM information_schema.tables
            WHERE table_schema = current_schema()
              AND table_name = 'ashlar_security_event_webhook_outbox';
            """;
        var command = new CommandDefinition(sql, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
        var count = await connectionHandle.Connection.ExecuteScalarAsync<int>(command);
        return count > 0;
    }

    private static async Task<SecurityEventWebhookOutboxDiagnosticSnapshot> QuerySnapshotAsync(
        PostgresConnectionHandle connectionHandle,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT
                COUNT(*) FILTER (
                    WHERE sent_at IS NULL
                      AND failed_at IS NULL
                      AND discarded_at IS NULL
                      AND available_at <= @Now
                      AND (locked_until IS NULL OR locked_until <= @Now)
                ) AS PendingCount,
                COUNT(*) FILTER (
                    WHERE sent_at IS NULL
                      AND failed_at IS NULL
                      AND discarded_at IS NULL
                      AND available_at > @Now
                ) AS ScheduledCount,
                COUNT(*) FILTER (
                    WHERE sent_at IS NULL
                      AND failed_at IS NULL
                      AND discarded_at IS NULL
                      AND locked_until > @Now
                ) AS LockedCount,
                COUNT(*) FILTER (
                    WHERE sent_at IS NULL
                      AND failed_at IS NULL
                      AND discarded_at IS NULL
                      AND locked_until IS NOT NULL
                      AND locked_until <= @Now
                ) AS ExpiredLockCount,
                COUNT(*) FILTER (
                    WHERE failed_at IS NOT NULL
                      AND discarded_at IS NULL
                ) AS FailedCount,
                MIN(available_at) FILTER (
                    WHERE sent_at IS NULL
                      AND failed_at IS NULL
                      AND discarded_at IS NULL
                      AND available_at <= @Now
                      AND (locked_until IS NULL OR locked_until <= @Now)
                ) AS OldestPendingAt,
                MIN(failed_at) FILTER (
                    WHERE failed_at IS NOT NULL
                      AND discarded_at IS NULL
                ) AS OldestFailedAt
            FROM ashlar_security_event_webhook_outbox;
        """;
        var command = new CommandDefinition(sql, new { Now = now }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
        return await connectionHandle.Connection.QuerySingleAsync<SecurityEventWebhookOutboxDiagnosticSnapshot>(command);
    }

    private void LogWebhookOutboxDiagnosticsFailed(Exception exception)
    {
        WebhookOutboxDiagnosticsFailed(_logger, exception);
    }
}
