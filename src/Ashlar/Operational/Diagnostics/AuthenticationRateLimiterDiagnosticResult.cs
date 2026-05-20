namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Represents a provider-neutral result for Ashlar authentication rate limiter diagnostics.
/// </summary>
/// <param name="Status">The diagnostic status value.</param>
/// <param name="ProviderName">The provider name value.</param>
/// <param name="Reason">The reason value.</param>
/// <param name="CheckedAt">The checked at value.</param>
/// <param name="Configured">The configured value.</param>
/// <param name="Distributed">The distributed value.</param>
/// <param name="Persistent">The persistent value.</param>
/// <param name="ExpiredRowCount">The expired row count value.</param>
/// <param name="ActiveKeyCount">The active key count value.</param>
/// <param name="BlockedKeyCount">The blocked key count value.</param>
/// <param name="CleanupConfigured">Whether rate limiter cleanup scheduling is enabled.</param>
/// <param name="CleanupInterval">The cleanup interval value.</param>
/// <param name="MaxCleanupRows">The max cleanup rows value.</param>
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
