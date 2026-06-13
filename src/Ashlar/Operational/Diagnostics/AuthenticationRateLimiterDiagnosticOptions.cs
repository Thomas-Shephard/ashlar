namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Describes provider capability and cleanup settings for authentication rate limiter diagnostics.
/// </summary>
/// <param name="Configured">Whether authentication rate limiting is registered.</param>
/// <param name="Distributed">Whether limiter state is shared across application instances.</param>
/// <param name="Persistent">Whether limiter state survives process restarts.</param>
/// <param name="CleanupConfigured">Whether expired limiter cleanup is enabled, when cleanup applies.</param>
/// <param name="CleanupInterval">Interval for expired limiter cleanup, when cleanup applies.</param>
/// <param name="MaxCleanupRows">Maximum number of expired limiter rows removed per cleanup run, when cleanup applies.</param>
public sealed record AuthenticationRateLimiterDiagnosticOptions(
    bool Configured,
    bool Distributed,
    bool Persistent,
    bool? CleanupConfigured,
    TimeSpan? CleanupInterval,
    int? MaxCleanupRows);
