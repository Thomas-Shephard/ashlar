namespace Ashlar.Identity.RateLimiting.Models;

/// <summary>
/// Represents the result status of a rate limit evaluation.
/// </summary>
public enum RateLimitStatus
{
    /// <summary>
    /// The attempt is allowed to proceed.
    /// </summary>
    Allowed = 0,

    /// <summary>
    /// The attempt has exceeded the allowed rate limit and is blocked.
    /// </summary>
    Blocked = 1
}


