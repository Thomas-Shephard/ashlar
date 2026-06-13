namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Display-safe aggregate state used to evaluate authentication rate limiter health.
/// </summary>
public sealed record AuthenticationRateLimiterDiagnosticSnapshot
{
    /// <summary>
    /// Expired rate-limit rows observed by the provider, when the diagnostic can count them.
    /// </summary>
    public long? ExpiredRowCount { get; init; }

    /// <summary>
    /// Active rate-limit buckets observed by the provider, when the diagnostic can count them.
    /// </summary>
    public long? ActiveKeyCount { get; init; }

    /// <summary>
    /// Currently blocked rate-limit buckets observed by the provider, when the diagnostic can count them.
    /// </summary>
    public long? BlockedKeyCount { get; init; }
}
