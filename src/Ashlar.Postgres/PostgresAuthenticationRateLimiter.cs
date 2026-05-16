using System.Data;
using Ashlar.Identity.RateLimiting;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Dapper;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Npgsql;

namespace Ashlar.Postgres;

/// <summary>
/// A PostgreSQL-backed rate limiter that supports distributed rate limiting across multiple application instances.
/// </summary>
public sealed class PostgresAuthenticationRateLimiter : IAuthenticationRateLimiter
{
    private static readonly Action<ILogger, Exception?> OpportunisticCleanupFailed =
        LoggerMessage.Define(
            LogLevel.Warning,
            new EventId(1000, nameof(OpportunisticCleanupFailed)),
            "PostgreSQL authentication rate limiter opportunistic cleanup failed.");

    private readonly NpgsqlDataSource _dataSource;
    private readonly TimeProvider _timeProvider;
    private readonly PostgresAuthenticationRateLimiterOptions _options;
    private readonly ILogger<PostgresAuthenticationRateLimiter> _logger;
    private DateTimeOffset _nextCleanupTime = DateTimeOffset.MinValue;
    private readonly object _cleanupLock = new();

    internal Func<NpgsqlConnection, NpgsqlTransaction, string, string, CancellationToken, Task>? AfterInsertForTesting { get; set; }

    /// <summary>
    /// Initializes a configured PostgreSQL authentication rate limiter.
    /// </summary>
    /// <param name="dataSource">The PostgreSQL data source.</param>
    /// <param name="timeProvider">The time provider.</param>
    /// <param name="options">The rate limiter options.</param>
    /// <param name="logger">The logger value.</param>
    public PostgresAuthenticationRateLimiter(
        NpgsqlDataSource dataSource,
        TimeProvider timeProvider,
        IOptions<PostgresAuthenticationRateLimiterOptions> options,
        ILogger<PostgresAuthenticationRateLimiter>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(dataSource);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(options);

        _dataSource = dataSource;
        _timeProvider = timeProvider;
        _options = options.Value;
        _logger = logger ?? NullLogger<PostgresAuthenticationRateLimiter>.Instance;
        if (!ValidateOptions(_options))
        {
            throw new ArgumentException("CleanupInterval must be greater than zero and MaxCleanupRows must be greater than zero.", nameof(options));
        }
    }

    /// <summary>
    /// Performs the check <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="attempt">The attempt value.</param>
    /// <param name="rule">The rule value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<RateLimitDecision> CheckAsync(RateLimitAttempt attempt, RateLimitRule rule, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(attempt);
        ArgumentNullException.ThrowIfNull(rule);

        ValidateRule(rule);

        await TryOpportunisticCleanupAsync();

        var now = _timeProvider.GetUtcNow();
        var purpose = attempt.Purpose ?? string.Empty;
        var key = attempt.Key;

        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);

        const string upsertSql =
            """
            INSERT INTO ashlar_rate_limits (purpose, rate_limit_key, count, window_start, expires_at)
            VALUES (@purpose, @key, 0, @now, @expiresAt)
            ON CONFLICT (purpose, rate_limit_key) DO NOTHING;
            """;

        var upsertCommand = new CommandDefinition(upsertSql, new
        {
            purpose,
            key,
            now,
            expiresAt = now + rule.Window
        }, transaction, cancellationToken: cancellationToken);

        const string selectSql =
            """
            SELECT count, window_start as WindowStart, blocked_until as BlockedUntil
            FROM ashlar_rate_limits
            WHERE purpose = @purpose AND rate_limit_key = @key
            FOR UPDATE;
            """;

        var selectCommand = new CommandDefinition(selectSql, new { purpose, key }, transaction, cancellationToken: cancellationToken);
        var state = await connection.QuerySingleOrDefaultAsync<RateLimitState>(selectCommand);
        if (state == null)
        {
            await connection.ExecuteAsync(upsertCommand);
            if (AfterInsertForTesting != null)
            {
                await AfterInsertForTesting(connection, transaction, purpose, key, cancellationToken);
            }

            state = await connection.QuerySingleOrDefaultAsync<RateLimitState>(selectCommand);
            if (state == null)
            {
                await connection.ExecuteAsync(upsertCommand);
                state = await connection.QuerySingleAsync<RateLimitState>(selectCommand);
            }
        }

        var decision = RateLimitEvaluator.Evaluate(state, rule, now);

        var updatedExpiresAt = state.BlockedUntil ?? state.WindowStart + rule.Window;

        const string updateSql =
            """
            UPDATE ashlar_rate_limits
            SET count = @Count, window_start = @WindowStart, blocked_until = @BlockedUntil, expires_at = @expiresAt
            WHERE purpose = @purpose AND rate_limit_key = @key;
            """;

        var updateCommand = new CommandDefinition(updateSql, new
        {
            state.Count,
            state.WindowStart,
            state.BlockedUntil,
            expiresAt = updatedExpiresAt,
            purpose,
            key
        }, transaction, cancellationToken: cancellationToken);

        await connection.ExecuteAsync(updateCommand);

        await transaction.CommitAsync(cancellationToken);

        return decision;
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

    internal static bool ValidateOptions(PostgresAuthenticationRateLimiterOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (options.CleanupInterval <= TimeSpan.Zero)
        {
            return false;
        }

        if (options.MaxCleanupRows <= 0)
        {
            return false;
        }

        return true;
    }

    internal Task TryOpportunisticCleanupAsync()
    {
        var now = _timeProvider.GetUtcNow();

        lock (_cleanupLock)
        {
            if (now < _nextCleanupTime)
            {
                return Task.CompletedTask;
            }

            _nextCleanupTime = now + _options.CleanupInterval;
        }

        _ = Task.Run(RunCleanupAsync, CancellationToken.None);

        return Task.CompletedTask;
    }

    private async Task RunCleanupAsync()
    {
        try
        {
            await CleanupExpiredRowsAsync(CancellationToken.None);
        }
        catch (Exception ex)
        {
            OpportunisticCleanupFailed(_logger, ex);
            // Cleanup is opportunistic; failures should not block authentication attempts.
        }
    }

    /// <summary>
    /// Performs the cleanup expired rows <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<int> CleanupExpiredRowsAsync(CancellationToken cancellationToken = default)
    {
        var now = _timeProvider.GetUtcNow();

        const string deleteSql =
            """
            DELETE FROM ashlar_rate_limits
            WHERE (purpose, rate_limit_key) IN (
                SELECT purpose, rate_limit_key
                FROM ashlar_rate_limits
                WHERE expires_at < @now
                FOR UPDATE SKIP LOCKED
                LIMIT @limit
            );
            """;

        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        var command = new CommandDefinition(deleteSql, new { now, limit = _options.MaxCleanupRows }, cancellationToken: cancellationToken);
        return await connection.ExecuteAsync(command);
    }
}
