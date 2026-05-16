using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.Identity.RateLimiting;

/// <summary>
/// Evaluates rate limit state transitions for authentication rate limiter implementations.
/// </summary>
/// <returns>The operation result.</returns>
public static class RateLimitEvaluator
{
    /// <summary>
    /// Applies the rate limit rule to the current state and returns the resulting decision.
    /// </summary>
    /// <param name="state">The state value.</param>
    /// <param name="rule">The rule value.</param>
    /// <param name="now">The now value.</param>
    /// <returns>The operation result.</returns>
    /// <remarks>
    /// Implementations should load the state, call this method, then persist the mutated state atomically.
    /// </remarks>
    public static RateLimitDecision Evaluate(RateLimitState state, RateLimitRule rule, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(rule);

        ResetExpiredWindow(state, rule, now);

        if (state.BlockedUntil.HasValue && now < state.BlockedUntil.Value)
        {
            return CreateBlockedDecision(state.BlockedUntil.Value);
        }

        if (state.Count < rule.PermitLimit)
        {
            return ConsumePermit(state, rule, now);
        }

        var blockedUntil = GetBlockedUntil(state, rule, now);
        state.BlockedUntil = blockedUntil;
        return CreateBlockedDecision(blockedUntil);
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

    private static DateTimeOffset GetBlockedUntil(RateLimitState state, RateLimitRule rule, DateTimeOffset now)
    {
        var windowEnd = state.WindowStart + rule.Window;
        if (!rule.BlockDuration.HasValue)
        {
            return windowEnd;
        }

        var blockEnd = now + rule.BlockDuration.Value;
        return blockEnd > windowEnd ? blockEnd : windowEnd;
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
}
