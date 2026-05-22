using System.Globalization;
using Ashlar.Operational.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Ashlar.Sqlite.RateLimiting;

internal sealed class SqliteAuthenticationRateLimiterDiagnostics(
    ISqliteConnectionProvider connectionProvider,
    TimeProvider timeProvider,
    ILogger<SqliteAuthenticationRateLimiterDiagnostics>? logger = null)
    : AuthenticationRateLimiterDiagnostics<SqliteConnectionHandle>(ProviderName, timeProvider)
{
    private const string ProviderName = "Sqlite";
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
    private readonly ILogger<SqliteAuthenticationRateLimiterDiagnostics> _logger = logger ?? NullLogger<SqliteAuthenticationRateLimiterDiagnostics>.Instance;

    protected override ValueTask<SqliteConnectionHandle> OpenConnectionAsync(CancellationToken cancellationToken)
    {
        return _connectionProvider.GetConnectionAsync(cancellationToken);
    }

    protected override async Task<bool> TableExistsAsync(SqliteConnectionHandle connectionHandle, CancellationToken cancellationToken)
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

    protected override async Task<AuthenticationRateLimiterDiagnosticSnapshot> QuerySnapshotAsync(
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

    protected override AuthenticationRateLimiterDiagnosticOptions CreateOptions()
    {
        return Options;
    }

    protected override void LogException(Exception exception)
    {
        RateLimiterDiagnosticsFailed(_logger, exception);
    }
}
