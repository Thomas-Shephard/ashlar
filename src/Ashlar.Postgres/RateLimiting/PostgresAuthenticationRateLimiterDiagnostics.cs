using Ashlar.Operational.Diagnostics;
using Dapper;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Ashlar.Postgres.RateLimiting;

internal sealed class PostgresAuthenticationRateLimiterDiagnostics(
    IPostgresConnectionProvider connectionProvider,
    IOptions<PostgresAuthenticationRateLimiterOptions> options,
    TimeProvider timeProvider,
    ILogger<PostgresAuthenticationRateLimiterDiagnostics>? logger = null) : IAuthenticationRateLimiterDiagnostics
{
    private const string ProviderName = "Postgres";
    private static readonly AuthenticationRateLimiterDiagnosticsRunner DiagnosticsRunner = new(ProviderName);

    private static readonly Action<ILogger, Exception?> RateLimiterDiagnosticsFailed =
        LoggerMessage.Define(
            LogLevel.Error,
            new EventId(1007, nameof(RateLimiterDiagnosticsFailed)),
            "PostgreSQL authentication rate limiter diagnostics failed.");

    private readonly IPostgresConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));
    private readonly PostgresAuthenticationRateLimiterOptions _options = (options ?? throw new ArgumentNullException(nameof(options))).Value;
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    private readonly ILogger<PostgresAuthenticationRateLimiterDiagnostics> _logger = logger ?? NullLogger<PostgresAuthenticationRateLimiterDiagnostics>.Instance;

    public async Task<AuthenticationRateLimiterDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default)
    {
        return await DiagnosticsRunner.CheckAsync(
            _timeProvider,
            new AuthenticationRateLimiterDiagnosticsContext<PostgresConnectionHandle>(
                _connectionProvider.GetConnectionAsync,
                TableExistsAsync,
                QuerySnapshotAsync,
                LogRateLimiterDiagnosticsFailed),
            new AuthenticationRateLimiterDiagnosticOptions(
                true,
                true,
                true,
                true,
                _options.CleanupInterval,
                _options.MaxCleanupRows),
            cancellationToken);
    }

    private static async Task<bool> TableExistsAsync(PostgresConnectionHandle connectionHandle, CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT COUNT(*)
            FROM information_schema.tables
            WHERE table_schema = current_schema()
              AND table_name = 'ashlar_rate_limits';
            """;
        var command = new CommandDefinition(sql, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
        var count = await connectionHandle.Connection.ExecuteScalarAsync<int>(command);
        return count > 0;
    }

    private static async Task<AuthenticationRateLimiterDiagnosticSnapshot> QuerySnapshotAsync(
        PostgresConnectionHandle connectionHandle,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT
                COUNT(*) FILTER (WHERE expires_at >= @Now) AS ActiveKeyCount,
                COUNT(*) FILTER (WHERE expires_at < @Now) AS ExpiredRowCount,
                COUNT(*) FILTER (WHERE blocked_until IS NOT NULL AND blocked_until > @Now) AS BlockedKeyCount
            FROM ashlar_rate_limits;
            """;
        var command = new CommandDefinition(sql, new { Now = now }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
        return await connectionHandle.Connection.QuerySingleAsync<AuthenticationRateLimiterDiagnosticSnapshot>(command);
    }

    private void LogRateLimiterDiagnosticsFailed(Exception exception)
    {
        RateLimiterDiagnosticsFailed(_logger, exception);
    }
}
