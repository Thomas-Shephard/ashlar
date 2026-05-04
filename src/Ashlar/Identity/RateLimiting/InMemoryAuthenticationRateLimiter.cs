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
            if (!_cache.TryGetValue(cacheKey, out CacheEntry? entry) || entry == null)
            {
                entry = new CacheEntry(new RateLimitState());
            }

            var state = entry.State;
            decision = RateLimitEvaluator.Evaluate(state, rule, now);

            var expiresAt = state.BlockedUntil ?? state.WindowStart + rule.Window;
            if (entry.ExpiresAt != expiresAt)
            {
                entry.ExpiresAt = expiresAt;
                _cache.Set(cacheKey, entry, new MemoryCacheEntryOptions
                {
                    Size = 1,
                    AbsoluteExpiration = expiresAt,
                    Priority = state.BlockedUntil.HasValue ? CacheItemPriority.High : CacheItemPriority.Low
                });
            }
        }

        return Task.FromResult(decision);
    }

    public void Dispose()
    {
        _cache.Dispose();
    }

    private sealed class CacheEntry(RateLimitState state)
    {
        public RateLimitState State { get; } = state;
        public DateTimeOffset? ExpiresAt { get; set; }
    }

    private sealed class TimeProviderSystemClock(TimeProvider timeProvider) : ISystemClock
    {
        public DateTimeOffset UtcNow => timeProvider.GetUtcNow();
    }
}
