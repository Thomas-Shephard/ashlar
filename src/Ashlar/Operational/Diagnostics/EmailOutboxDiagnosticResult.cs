namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Describes aggregate diagnostic state for the Ashlar email outbox.
/// </summary>
/// <param name="Status">Overall diagnostic status for the outbox check.</param>
/// <param name="ProviderName">Persistence provider that produced the diagnostic result.</param>
/// <param name="Reason">Optional provider-safe reason when the check is unavailable, degraded, or failed.</param>
/// <param name="CheckedAt">UTC time when the diagnostic check completed.</param>
/// <param name="PendingCount">Number of messages ready for delivery.</param>
/// <param name="ScheduledCount">Number of messages scheduled for future delivery.</param>
/// <param name="LockedCount">Number of messages currently locked by a dispatcher.</param>
/// <param name="ExpiredLockCount">Number of locked messages whose delivery lock has expired.</param>
/// <param name="FailedCount">Number of messages that exhausted delivery attempts.</param>
/// <param name="SensitivePendingCount">Pending messages marked as containing sensitive body content.</param>
/// <param name="SensitiveScheduledCount">Scheduled messages marked as containing sensitive body content.</param>
/// <param name="SensitiveLockedCount">Locked messages marked as containing sensitive body content.</param>
/// <param name="SensitiveFailedCount">Failed messages marked as containing sensitive body content.</param>
/// <param name="OldestPendingAt">Oldest pending message timestamp, when available.</param>
/// <param name="OldestFailedAt">Oldest failed message timestamp, when available.</param>
/// <param name="MaxAttempts">Configured maximum delivery attempts.</param>
/// <param name="PollingInterval">Configured dispatcher polling interval.</param>
/// <param name="BatchSize">Configured dispatcher batch size.</param>
public sealed record EmailOutboxDiagnosticResult(
    AshlarDiagnosticStatus Status,
    string ProviderName,
    string? Reason,
    DateTimeOffset CheckedAt,
    long? PendingCount,
    long? ScheduledCount,
    long? LockedCount,
    long? ExpiredLockCount,
    long? FailedCount,
    long? SensitivePendingCount,
    long? SensitiveScheduledCount,
    long? SensitiveLockedCount,
    long? SensitiveFailedCount,
    DateTimeOffset? OldestPendingAt,
    DateTimeOffset? OldestFailedAt,
    int? MaxAttempts,
    TimeSpan? PollingInterval,
    int? BatchSize);
