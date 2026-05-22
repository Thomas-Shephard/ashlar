namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Represents safe aggregate authentication rate limiter state.
/// </summary>
public sealed record AuthenticationRateLimiterDiagnosticSnapshot
{
    /// <summary>
    /// Gets or sets the expired row count value.
    /// </summary>
    public long? ExpiredRowCount { get; init; }

    /// <summary>
    /// Gets or sets the active key count value.
    /// </summary>
    public long? ActiveKeyCount { get; init; }

    /// <summary>
    /// Gets or sets the blocked key count value.
    /// </summary>
    public long? BlockedKeyCount { get; init; }
}
