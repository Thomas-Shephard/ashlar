namespace Ashlar.Identity.RateLimiting.Models;

/// <summary>
/// Identifies whether an authentication rate-limit check permits or blocks the attempted operation.
/// </summary>
public enum RateLimitStatus
{
    /// <summary>
    /// The attempt may proceed. This can include consumed permits, disabled scopes, or excluded users.
    /// </summary>
    Allowed = 0,

    /// <summary>
    /// The attempt must not proceed because the applicable rate-limit rule blocked it.
    /// </summary>
    Blocked = 1
}
