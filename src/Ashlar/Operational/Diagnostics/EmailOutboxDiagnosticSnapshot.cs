namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Display-safe aggregate state used to evaluate email outbox health.
/// </summary>
public sealed record EmailOutboxDiagnosticSnapshot
{
    /// <summary>
    /// Messages ready to dispatch now.
    /// </summary>
    public long PendingCount { get; init; }

    /// <summary>
    /// Messages scheduled for future dispatch.
    /// </summary>
    public long ScheduledCount { get; init; }

    /// <summary>
    /// Messages currently claimed by a dispatcher.
    /// </summary>
    public long LockedCount { get; init; }

    /// <summary>
    /// Locked messages whose lease has expired.
    /// </summary>
    public long ExpiredLockCount { get; init; }

    /// <summary>
    /// Messages that exhausted dispatch attempts.
    /// </summary>
    public long FailedCount { get; init; }

    /// <summary>
    /// Ready-to-dispatch messages whose body contains live secret material.
    /// </summary>
    public long SensitivePendingCount { get; init; }

    /// <summary>
    /// Future-dispatch messages whose body contains live secret material.
    /// </summary>
    public long SensitiveScheduledCount { get; init; }

    /// <summary>
    /// Claimed messages whose body contains live secret material.
    /// </summary>
    public long SensitiveLockedCount { get; init; }

    /// <summary>
    /// Failed messages whose body contains live secret material.
    /// </summary>
    public long SensitiveFailedCount { get; init; }

    /// <summary>
    /// Oldest ready-to-dispatch message timestamp, when any exist.
    /// </summary>
    public DateTimeOffset? OldestPendingAt { get; init; }

    /// <summary>
    /// Oldest failed message timestamp, when any exist.
    /// </summary>
    public DateTimeOffset? OldestFailedAt { get; init; }
}
