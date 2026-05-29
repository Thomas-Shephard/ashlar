namespace Ashlar.Identity.RateLimiting.Models;

/// <summary>
/// Describes one authentication rate-limit bucket check.
/// </summary>
/// <param name="Purpose">The operation purpose being limited.</param>
/// <param name="DimensionName">The safe bucket dimension name.</param>
/// <param name="DimensionValue">The safe bucket dimension value.</param>
/// <param name="Rule">The rule to enforce.</param>
public sealed record AuthenticationRateLimitCheck(
    string Purpose,
    string DimensionName,
    string DimensionValue,
    RateLimitRule Rule)
{
    /// <summary>
    /// Gets the optional provider identity for provider-scoped buckets.
    /// </summary>
    public AuthenticationProviderKey? ProviderKey { get; init; }

    /// <summary>
    /// Gets the optional authentication context.
    /// </summary>
    public AuthenticationContext? Context { get; init; }

    /// <summary>
    /// Gets the optional normalized tenant scope override.
    /// </summary>
    public Guid? TenantId { get; init; }

    /// <summary>
    /// Gets the optional user identity metadata.
    /// </summary>
    public Guid? UserId { get; init; }

    /// <summary>
    /// Gets the optional email metadata. This value is normalized before it reaches the rate limiter.
    /// </summary>
    public string? Email { get; init; }
}
