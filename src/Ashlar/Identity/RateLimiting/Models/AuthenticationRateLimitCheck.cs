namespace Ashlar.Identity.RateLimiting.Models;

/// <summary>
/// Describes one authentication rate-limit bucket check.
/// </summary>
/// <param name="Purpose">The operation purpose being limited.</param>
/// <param name="DimensionName">Normalized dimension name used to partition rate-limit buckets.</param>
/// <param name="DimensionValue">Safe bucket value, such as a normalized email, source, or token hash.</param>
/// <param name="Rule">The rule to enforce.</param>
public sealed record AuthenticationRateLimitCheck(
    string Purpose,
    string DimensionName,
    string DimensionValue,
    RateLimitRule Rule)
{
    /// <summary>
    /// Optional provider identity for provider-scoped buckets.
    /// </summary>
    public AuthenticationProviderKey? ProviderKey { get; init; }

    /// <summary>
    /// Optional authentication context used for source, tenant, and correlation metadata.
    /// </summary>
    public AuthenticationContext? Context { get; init; }

    /// <summary>
    /// Optional normalized tenant scope override.
    /// </summary>
    public Guid? TenantId { get; init; }

    /// <summary>
    /// Optional user identity metadata.
    /// </summary>
    public Guid? UserId { get; init; }

    /// <summary>
    /// Optional email metadata after normalization for rate-limit bucketing.
    /// </summary>
    public string? Email { get; init; }
}
