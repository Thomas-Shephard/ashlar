using Microsoft.Extensions.Caching.Memory;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Microsoft.Extensions.Internal;

namespace Ashlar.Identity.RateLimiting;

/// <summary>
/// An in-memory, thread-safe rate limiter suitable for development or single-instance deployments.
/// </summary>
public sealed class InMemoryAuthenticationRateLimiter : IAuthenticationRateLimiter, IDisposable
{
    private readonly TimeProvider _timeProvider;
    private readonly MemoryCache _cache;
    private readonly object[] _locks;

    // ReSharper disable once InconsistentlySynchronizedField
    internal int StateCount => _cache.Count;

    public InMemoryAuthenticationRateLimiter(TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        _timeProvider = timeProvider;
        _cache = new MemoryCache(new MemoryCacheOptions
        {
            SizeLimit = 100_000,
            Clock = new TimeProviderSystemClock(timeProvider)
        });

        _locks = new object[256];
        for (int i = 0; i < _locks.Length; i++)
        {
            _locks[i] = new object();
        }
    }

    public Task<RateLimitDecision> CheckAsync(RateLimitAttempt attempt, RateLimitRule rule, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(attempt);
        ArgumentNullException.ThrowIfNull(rule);

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

        cancellationToken.ThrowIfCancellationRequested();
        var now = _timeProvider.GetUtcNow();
        var cacheKey = (attempt.Purpose, attempt.Key);

        var lockObj = _locks[(cacheKey.GetHashCode() & 0x7FFFFFFF) % _locks.Length];

        RateLimitDecision decision;
        lock (lockObj)
        {
            if (!_cache.TryGetValue(cacheKey, out RateLimitState? state) || state == null)
            {
                state = new RateLimitState();
            }

            ResetExpiredWindow(state, rule, now);
            decision = EvaluateDecision(state, rule, now);

            var expiresAt = state.BlockedUntil ?? state.WindowStart + rule.Window;
            if (state.ExpiresAt != expiresAt)
            {
                state.ExpiresAt = expiresAt;
                _cache.Set(cacheKey, state, new MemoryCacheEntryOptions
                {
                    Size = 1,
                    AbsoluteExpiration = expiresAt,
                    Priority = state.BlockedUntil.HasValue ? CacheItemPriority.High : CacheItemPriority.Low
                });
            }
        }

        return Task.FromResult(decision);
    }

    private static void ResetExpiredWindow(RateLimitState state, RateLimitRule rule, DateTimeOffset now)
    {
        bool isWindowExpired = now >= state.WindowStart + rule.Window && state.BlockedUntil == null;
        bool isBlockExpired = state.BlockedUntil.HasValue && now >= state.BlockedUntil.Value;

        if (isWindowExpired || isBlockExpired)
        {
            state.Count = 0;
            state.WindowStart = now;
            state.BlockedUntil = null;
        }
    }

    private static RateLimitDecision EvaluateDecision(RateLimitState state, RateLimitRule rule, DateTimeOffset now)
    {
        if (state.BlockedUntil.HasValue && now < state.BlockedUntil.Value)
        {
            return CreateBlockedDecision(state.BlockedUntil.Value);
        }

        if (state.Count < rule.PermitLimit)
        {
            return ConsumePermit(state, rule, now);
        }

        var windowEnd = state.WindowStart + rule.Window;
        var blockedUntil = windowEnd;

        if (rule.BlockDuration.HasValue)
        {
            var blockEnd = now + rule.BlockDuration.Value;
            blockedUntil = blockEnd > windowEnd ? blockEnd : windowEnd;
        }

        state.BlockedUntil = blockedUntil;
        return CreateBlockedDecision(blockedUntil);
    }

    private static RateLimitDecision CreateBlockedDecision(DateTimeOffset blockedUntil) =>
        new()
        {
            Status = RateLimitStatus.Blocked,
            Remaining = 0,
            RetryAfter = blockedUntil,
            WindowResetAt = blockedUntil
        };

    private static RateLimitDecision ConsumePermit(RateLimitState state, RateLimitRule rule, DateTimeOffset now)
    {
        if (state.Count == 0)
        {
            state.WindowStart = now;
        }

        state.Count++;
        return new RateLimitDecision
        {
            Status = RateLimitStatus.Allowed,
            Remaining = rule.PermitLimit - state.Count,
            RetryAfter = null,
            WindowResetAt = state.WindowStart + rule.Window
        };
    }

    public void Dispose()
    {
        _cache.Dispose();
    }

    private sealed class RateLimitState
    {
        public int Count { get; set; }
        public DateTimeOffset WindowStart { get; set; }
        public DateTimeOffset? BlockedUntil { get; set; }
        public DateTimeOffset? ExpiresAt { get; set; }
    }

    private sealed class TimeProviderSystemClock(TimeProvider timeProvider) : ISystemClock
    {
        public DateTimeOffset UtcNow => timeProvider.GetUtcNow();
    }
}
