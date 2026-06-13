namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Represents a provider-neutral result for Ashlar authentication rate limiter diagnostics.
/// </summary>
/// <param name="Status">Overall diagnostic <paramref name="Status" /> for the rate limiter.</param>
/// <param name="ProviderName">Provider that produced the diagnostic result.</param>
/// <param name="Reason">Optional provider-safe reason when the check is unavailable, degraded, or failed.</param>
/// <param name="CheckedAt">UTC time the diagnostic was evaluated.</param>
/// <param name="Configured">Whether rate limiter services are registered.</param>
/// <param name="Distributed">Whether the limiter coordinates attempts across app instances.</param>
/// <param name="Persistent">Whether limiter state survives process restarts.</param>
/// <param name="ExpiredRowCount">Expired limiter rows observed by providers that can report them.</param>
/// <param name="ActiveKeyCount">Active limiter keys observed by providers that can report them.</param>
/// <param name="BlockedKeyCount">Blocked limiter keys observed by providers that can report them.</param>
/// <param name="CleanupConfigured">Whether rate limiter cleanup scheduling is enabled.</param>
/// <param name="CleanupInterval">Registered cleanup interval, when cleanup is enabled.</param>
/// <param name="MaxCleanupRows">Maximum rows cleaned per cleanup pass, when applicable.</param>
public sealed record AuthenticationRateLimiterDiagnosticResult(
    AshlarDiagnosticStatus Status,
    string ProviderName,
    string? Reason,
    DateTimeOffset CheckedAt,
    bool Configured,
    bool Distributed,
    bool Persistent,
    long? ExpiredRowCount,
    long? ActiveKeyCount,
    long? BlockedKeyCount,
    bool? CleanupConfigured,
    TimeSpan? CleanupInterval,
    int? MaxCleanupRows);
