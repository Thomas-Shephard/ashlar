using System.Globalization;
using Ashlar.Operational.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Ashlar.Sqlite.RateLimiting;

internal sealed class SqliteAuthenticationRateLimiterDiagnostics(
    ISqliteConnectionProvider connectionProvider,
    TimeProvider timeProvider,
    ILogger<SqliteAuthenticationRateLimiterDiagnostics>? logger = null) : IAuthenticationRateLimiterDiagnostics
{
    private const string ProviderName = "Sqlite";
    private static readonly AuthenticationRateLimiterDiagnosticsRunner DiagnosticsRunner = new(ProviderName);
    private static readonly AuthenticationRateLimiterDiagnosticOptions Options = new(
        true,
        false,
        true,
        null,
        null,
        null);

    private static readonly Action<ILogger, Exception?> RateLimiterDiagnosticsFailed =
        LoggerMessage.Define(
            LogLevel.Error,
            new EventId(1005, nameof(RateLimiterDiagnosticsFailed)),
            "SQLite authentication rate limiter diagnostics failed.");

    private readonly ISqliteConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    private readonly ILogger<SqliteAuthenticationRateLimiterDiagnostics> _logger = logger ?? NullLogger<SqliteAuthenticationRateLimiterDiagnostics>.Instance;

    public async Task<AuthenticationRateLimiterDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default)
    {
        return await DiagnosticsRunner.CheckAsync(
            _timeProvider,
            new AuthenticationRateLimiterDiagnosticsContext<SqliteConnectionHandle>(
                _connectionProvider.GetConnectionAsync,
                TableExistsAsync,
                QuerySnapshotAsync,
                LogRateLimiterDiagnosticsFailed),
            Options,
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
              AND name = 'ashlar_rate_limits';
            """;
        var result = await command.ExecuteScalarAsync(cancellationToken);
        return Convert.ToInt32(result, CultureInfo.InvariantCulture) > 0;
    }

    private static async Task<AuthenticationRateLimiterDiagnosticSnapshot> QuerySnapshotAsync(
        SqliteConnectionHandle connectionHandle,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await using var command = connectionHandle.Connection.CreateCommand();
        command.Transaction = connectionHandle.Transaction;
        command.CommandText = """
            SELECT
                COALESCE(SUM(CASE WHEN expires_at >= $now THEN 1 ELSE 0 END), 0) AS active_key_count,
                COALESCE(SUM(CASE WHEN expires_at < $now THEN 1 ELSE 0 END), 0) AS expired_row_count,
                COALESCE(SUM(CASE WHEN blocked_until IS NOT NULL AND blocked_until > $now THEN 1 ELSE 0 END), 0) AS blocked_key_count
            FROM ashlar_rate_limits;
            """;
        command.AddDateTimeOffsetParameter("$now", now);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        await reader.ReadAsync(cancellationToken);
        return new AuthenticationRateLimiterDiagnosticSnapshot
        {
            ActiveKeyCount = reader.GetInt64(reader.GetOrdinal("active_key_count")),
            ExpiredRowCount = reader.GetInt64(reader.GetOrdinal("expired_row_count")),
            BlockedKeyCount = reader.GetInt64(reader.GetOrdinal("blocked_key_count"))
        };
    }

    private void LogRateLimiterDiagnosticsFailed(Exception exception)
    {
        RateLimiterDiagnosticsFailed(_logger, exception);
    }
}
