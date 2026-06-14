using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace Ashlar.Redis.RateLimiting;

/// <summary>
/// A Redis-backed authentication rate limiter that supports distributed rate limiting across application instances.
/// </summary>
public sealed class RedisAuthenticationRateLimiter : IAuthenticationRateLimiter
{
    private static readonly LuaScript Script = LuaScript.Prepare("""
        local hash = redis.call('HMGET', @key, 'count', 'windowStart', 'blockedUntil')
        local count = tonumber(hash[1] or '0')
        local windowStart = tonumber(hash[2] or @now)
        local blockedUntil = nil
        if hash[3] then
            blockedUntil = tonumber(hash[3])
        end

        local now = tonumber(@now)
        local permitLimit = tonumber(@permitLimit)
        local windowMs = tonumber(@windowMs)
        local blockMs = tonumber(@blockMs)
        local skewMs = tonumber(@skewMs)

        if ((now >= windowStart + windowMs) and (blockedUntil == nil)) or ((blockedUntil ~= nil) and (now >= blockedUntil)) then
            count = 0
            windowStart = now
            blockedUntil = nil
        end

        local status
        local remaining
        local retryAfter = -1
        local resetAt

        if blockedUntil ~= nil and now < blockedUntil then
            status = 1
            remaining = 0
            retryAfter = blockedUntil
            resetAt = blockedUntil
        elseif count < permitLimit then
            if count == 0 then
                windowStart = now
            end
            count = count + 1
            status = 0
            remaining = permitLimit - count
            resetAt = windowStart + windowMs
        else
            local windowEnd = windowStart + windowMs
            local blockEnd = windowEnd
            if blockMs > 0 and now + blockMs > windowEnd then
                blockEnd = now + blockMs
            end
            blockedUntil = blockEnd
            status = 1
            remaining = 0
            retryAfter = blockEnd
            resetAt = blockEnd
        end

        if blockedUntil == nil then
            redis.call('HSET', @key, 'count', count, 'windowStart', windowStart, 'purpose', @purpose, 'expiresAt', resetAt)
            redis.call('HDEL', @key, 'blockedUntil')
        else
            redis.call('HSET', @key, 'count', count, 'windowStart', windowStart, 'blockedUntil', blockedUntil, 'purpose', @purpose, 'expiresAt', resetAt)
        end

        local ttlMs = resetAt - now + skewMs
        if ttlMs < 1 then
            ttlMs = 1
        end
        redis.call('PEXPIRE', @key, ttlMs)

        return { status, remaining, retryAfter, resetAt }
        """);

    private readonly Func<ValueTask<IConnectionMultiplexer>> _getConnectionAsync;
    private readonly RedisAuthenticationRateLimiterOptions _options;
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Initializes a configured Redis authentication rate limiter.
    /// </summary>
    /// <param name="connection">The Redis connection multiplexer.</param>
    /// <param name="options">The Redis rate limiter options.</param>
    /// <param name="timeProvider">The time provider.</param>
    public RedisAuthenticationRateLimiter(
        IConnectionMultiplexer connection,
        IOptions<RedisAuthenticationRateLimiterOptions> options,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _getConnectionAsync = () => ValueTask.FromResult(connection);
        _options = options.Value;
        _timeProvider = timeProvider;

        if (!RedisAuthenticationRateLimiterOptions.Validate(_options))
        {
            throw new ArgumentException("Redis rate limiter options are invalid.", nameof(options));
        }
    }

    internal RedisAuthenticationRateLimiter(
        RedisAuthenticationRateLimiterConnection connectionWrapper,
        IOptions<RedisAuthenticationRateLimiterOptions> options,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(connectionWrapper);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _getConnectionAsync = connectionWrapper.GetConnectionAsync;
        _options = options.Value;
        _timeProvider = timeProvider;

        if (!RedisAuthenticationRateLimiterOptions.Validate(_options))
        {
            throw new ArgumentException("Redis rate limiter options are invalid.", nameof(options));
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
        ArgumentException.ThrowIfNullOrWhiteSpace(attempt.Key);
        ValidateRule(rule);
        cancellationToken.ThrowIfCancellationRequested();

        var now = _timeProvider.GetUtcNow();
        var connection = await _getConnectionAsync();
        var database = connection.GetDatabase(_options.Database ?? -1);
        var redisKey = RedisRateLimitKeyBuilder.Build(_options.KeyPrefix, attempt.Purpose, attempt.Key);

        var scriptResult = await Script.EvaluateAsync(database, new
        {
            key = (RedisKey)redisKey,
            purpose = attempt.Purpose ?? string.Empty,
            now = now.ToUnixTimeMilliseconds(),
            permitLimit = rule.PermitLimit,
            windowMs = ToPositiveMilliseconds(rule.Window, nameof(rule)),
            blockMs = rule.BlockDuration.HasValue ? ToPositiveMilliseconds(rule.BlockDuration.Value, nameof(rule)) : 0,
            skewMs = (long)_options.ExpirationSkew.TotalMilliseconds
        });
        var result = ConvertScriptResult(scriptResult);

        cancellationToken.ThrowIfCancellationRequested();

        var status = (int)result[0];
        var retryAfterUnixMs = (long)result[2];
        var resetAtUnixMs = (long)result[3];

        return new RateLimitDecision
        {
            Status = status == 0 ? RateLimitStatus.Allowed : RateLimitStatus.Blocked,
            Remaining = (int)result[1],
            RetryAfter = retryAfterUnixMs < 0 ? null : DateTimeOffset.FromUnixTimeMilliseconds(retryAfterUnixMs),
            WindowResetAt = DateTimeOffset.FromUnixTimeMilliseconds(resetAtUnixMs)
        };
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

    private static long ToPositiveMilliseconds(TimeSpan value, string parameterName)
    {
        var milliseconds = (long)value.TotalMilliseconds;
        if (milliseconds <= 0)
        {
            throw new ArgumentOutOfRangeException(parameterName, "Rate limit durations must be at least one millisecond.");
        }

        return milliseconds;
    }

    private static RedisResult[] ConvertScriptResult(RedisResult scriptResult)
    {
        try
        {
            var result = (RedisResult[]?)scriptResult;
            ArgumentNullException.ThrowIfNull(result);
            if (result.Length != 4)
            {
                throw new InvalidOperationException("Redis rate limiter returned an invalid response.");
            }

            return result;
        }
        catch (Exception ex) when (ex is InvalidCastException or ArgumentNullException)
        {
            throw new InvalidOperationException("Redis rate limiter returned an invalid response.", ex);
        }
    }
}
