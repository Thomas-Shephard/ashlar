namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Represents provider capability and cleanup settings for authentication rate limiter diagnostics.
/// </summary>
/// <param name="Configured">The <paramref name="Configured" /> value.</param>
/// <param name="Distributed">The distributed value.</param>
/// <param name="Persistent">The persistent value.</param>
/// <param name="CleanupConfigured">The cleanup configuration value.</param>
/// <param name="CleanupInterval">The cleanup interval value.</param>
/// <param name="MaxCleanupRows">The max cleanup rows value.</param>
public sealed record AuthenticationRateLimiterDiagnosticOptions(
    bool Configured,
    bool Distributed,
    bool Persistent,
    bool? CleanupConfigured,
    TimeSpan? CleanupInterval,
    int? MaxCleanupRows);
