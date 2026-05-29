using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.Identity.RateLimiting;

/// <summary>
/// Provides shared validation for authentication rate-limit rules.
/// </summary>
public static class AuthenticationRateLimitRuleValidator
{
    /// <summary>
    /// Returns whether a rate-limit rule can be enforced safely.
    /// </summary>
    /// <param name="rule">The rate-limit rule.</param>
    /// <returns><see langword="true" /> when the rule is valid.</returns>
    public static bool IsValid(RateLimitRule? rule)
    {
        return rule is { PermitLimit: > 0 }
            && rule.Window > TimeSpan.Zero
            && (!rule.BlockDuration.HasValue || rule.BlockDuration.Value > TimeSpan.Zero);
    }
}
