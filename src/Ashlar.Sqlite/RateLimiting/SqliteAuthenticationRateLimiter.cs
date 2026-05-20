using Ashlar.Identity.RateLimiting;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.Sqlite.RateLimiting;

/// <summary>
/// A SQLite-backed authentication rate limiter for single-instance deployments.
/// </summary>
public sealed class SqliteAuthenticationRateLimiter : IAuthenticationRateLimiter
{
    private const string PurposeParameter = "$purpose";
    private const string KeyParameter = "$key";
    private const string NowParameter = "$now";
    private const string ExpiresAtParameter = "$expiresAt";
    private const string CountParameter = "$count";
    private const string WindowStartParameter = "$windowStart";
    private const string BlockedUntilParameter = "$blockedUntil";
    private const string LimitParameter = "$limit";

    private readonly ISqliteConnectionProvider _connectionProvider;
    private readonly IAshlarTransactionProvider _transactionProvider;
    private readonly TimeProvider _timeProvider;

    internal Func<SqliteConnectionHandle, string, string, CancellationToken, Task>? AfterInsertForTesting { get; set; }

    /// <summary>
    /// Initializes a configured SQLite authentication rate limiter.
    /// </summary>
    /// <param name="connectionProvider">The SQLite connection provider.</param>
    /// <param name="transactionProvider">The Ashlar transaction provider.</param>
    /// <param name="timeProvider">The time provider.</param>
    public SqliteAuthenticationRateLimiter(
        ISqliteConnectionProvider connectionProvider,
        IAshlarTransactionProvider transactionProvider,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(connectionProvider);
        ArgumentNullException.ThrowIfNull(transactionProvider);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _connectionProvider = connectionProvider;
        _transactionProvider = transactionProvider;
        _timeProvider = timeProvider;
    }

    public async Task<RateLimitDecision> CheckAsync(RateLimitAttempt attempt, RateLimitRule rule, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(attempt);
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentException.ThrowIfNullOrWhiteSpace(attempt.Key);
        ValidateRule(rule);

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);
        var decision = await CheckCoreAsync(attempt, rule, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return decision;
    }

    /// <summary>
    /// Deletes expired rate-limit rows in a bounded batch.
    /// </summary>
    /// <param name="maxRows">The maximum number of rows to delete.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The deleted row count.</returns>
    public async Task<int> CleanupExpiredRowsAsync(int maxRows = 500, CancellationToken cancellationToken = default)
    {
        if (maxRows <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxRows), "Max rows must be greater than zero.");
        }

        const string sql = """
            DELETE FROM ashlar_rate_limits
            WHERE rowid IN (
                SELECT rowid
                FROM ashlar_rate_limits
                WHERE expires_at < $now
                ORDER BY expires_at, purpose, rate_limit_key
                LIMIT $limit
            );
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddDateTimeOffsetParameter(NowParameter, _timeProvider.GetUtcNow());
        command.AddParameter(LimitParameter, maxRows);

        return await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private async Task<RateLimitDecision> CheckCoreAsync(RateLimitAttempt attempt, RateLimitRule rule, CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow();
        var purpose = attempt.Purpose ?? string.Empty;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await InsertIfMissingAsync(handle, purpose, attempt.Key, now, rule.Window, cancellationToken);
        if (AfterInsertForTesting != null)
        {
            await AfterInsertForTesting(handle, purpose, attempt.Key, cancellationToken);
        }

        var state = await ReadStateAsync(handle, purpose, attempt.Key, now, cancellationToken);

        var decision = RateLimitEvaluator.Evaluate(state, rule, now);
        var expiresAt = state.BlockedUntil ?? state.WindowStart + rule.Window;
        await UpdateStateAsync(handle, purpose, attempt.Key, state, expiresAt, cancellationToken);
        return decision;
    }

    private static async Task InsertIfMissingAsync(
        SqliteConnectionHandle handle,
        string purpose,
        string key,
        DateTimeOffset now,
        TimeSpan window,
        CancellationToken cancellationToken)
    {
        const string sql = """
            INSERT OR IGNORE INTO ashlar_rate_limits (purpose, rate_limit_key, count, window_start, expires_at)
            VALUES ($purpose, $key, 0, $now, $expiresAt);
            """;

        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddParameter(PurposeParameter, purpose);
        command.AddParameter(KeyParameter, key);
        command.AddDateTimeOffsetParameter(NowParameter, now);
        command.AddDateTimeOffsetParameter(ExpiresAtParameter, now + window);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task UpsertStateAsync(
        SqliteConnectionHandle handle,
        string purpose,
        string key,
        RateLimitState state,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken)
    {
        const string sql = """
            INSERT INTO ashlar_rate_limits (purpose, rate_limit_key, count, window_start, blocked_until, expires_at)
            VALUES ($purpose, $key, $count, $windowStart, $blockedUntil, $expiresAt)
            ON CONFLICT (purpose, rate_limit_key) DO UPDATE SET
                count = excluded.count,
                window_start = excluded.window_start,
                blocked_until = excluded.blocked_until,
                expires_at = excluded.expires_at;
            """;

        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        AddStateParameters(command, purpose, key, state, expiresAt);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<RateLimitState> ReadStateAsync(
        SqliteConnectionHandle handle,
        string purpose,
        string key,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT count, window_start, blocked_until
            FROM ashlar_rate_limits
            WHERE purpose = $purpose AND rate_limit_key = $key;
            """;

        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddParameter(PurposeParameter, purpose);
        command.AddParameter(KeyParameter, key);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return new RateLimitState { WindowStart = now };
        }

        return new RateLimitState
        {
            Count = reader.GetInt32ByName("count"),
            WindowStart = reader.GetDateTimeOffsetFromText("window_start"),
            BlockedUntil = reader.GetNullableDateTimeOffsetFromText("blocked_until")
        };
    }

    private static async Task UpdateStateAsync(
        SqliteConnectionHandle handle,
        string purpose,
        string key,
        RateLimitState state,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken)
    {
        const string sql = """
            UPDATE ashlar_rate_limits
            SET count = $count,
                window_start = $windowStart,
                blocked_until = $blockedUntil,
                expires_at = $expiresAt
            WHERE purpose = $purpose AND rate_limit_key = $key;
            """;

        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        AddStateParameters(command, purpose, key, state, expiresAt);
        if (await command.ExecuteNonQueryAsync(cancellationToken) == 0)
        {
            await UpsertStateAsync(handle, purpose, key, state, expiresAt, cancellationToken);
        }
    }

    private static void AddStateParameters(
        Microsoft.Data.Sqlite.SqliteCommand command,
        string purpose,
        string key,
        RateLimitState state,
        DateTimeOffset expiresAt)
    {
        command.AddParameter(PurposeParameter, purpose);
        command.AddParameter(KeyParameter, key);
        command.AddParameter(CountParameter, state.Count);
        command.AddDateTimeOffsetParameter(WindowStartParameter, state.WindowStart);
        command.AddNullableDateTimeOffsetParameter(BlockedUntilParameter, state.BlockedUntil);
        command.AddDateTimeOffsetParameter(ExpiresAtParameter, expiresAt);
    }

    private static void ValidateRule(RateLimitRule rule)
    {
        if (rule.PermitLimit <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(rule), "Permit limit must be greater than zero.");
        }

        if (rule.Window <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(rule), "Window must be greater than zero.");
        }

        if (rule.BlockDuration.HasValue && rule.BlockDuration.Value <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(rule), "Block duration must be greater than zero if specified.");
        }
    }
}






