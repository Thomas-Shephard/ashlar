namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Represents provider-specific security event webhook outbox aggregate state used to build diagnostics.
/// </summary>
public sealed record SecurityEventWebhookOutboxDiagnosticSnapshot
{
    /// <summary>
    /// Gets the pending count.
    /// </summary>
    public long PendingCount { get; init; }

    /// <summary>
    /// Gets the scheduled count.
    /// </summary>
    public long ScheduledCount { get; init; }

    /// <summary>
    /// Gets the locked count.
    /// </summary>
    public long LockedCount { get; init; }

    /// <summary>
    /// Gets the expired lock count.
    /// </summary>
    public long ExpiredLockCount { get; init; }

    /// <summary>
    /// Gets the failed count.
    /// </summary>
    public long FailedCount { get; init; }

    /// <summary>
    /// Gets the oldest pending timestamp.
    /// </summary>
    public DateTimeOffset? OldestPendingAt { get; init; }

    /// <summary>
    /// Gets the oldest failed timestamp.
    /// </summary>
    public DateTimeOffset? OldestFailedAt { get; init; }
}
