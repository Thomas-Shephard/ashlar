namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Display-safe aggregate state used to evaluate security event webhook outbox health.
/// </summary>
public sealed record SecurityEventWebhookOutboxDiagnosticSnapshot
{
    /// <summary>
    /// Webhook deliveries ready to dispatch now.
    /// </summary>
    public long PendingCount { get; init; }

    /// <summary>
    /// Webhook deliveries scheduled for future dispatch.
    /// </summary>
    public long ScheduledCount { get; init; }

    /// <summary>
    /// Webhook deliveries currently claimed by a dispatcher.
    /// </summary>
    public long LockedCount { get; init; }

    /// <summary>
    /// Claimed webhook deliveries whose lease has expired.
    /// </summary>
    public long ExpiredLockCount { get; init; }

    /// <summary>
    /// Webhook deliveries that exhausted dispatch attempts.
    /// </summary>
    public long FailedCount { get; init; }

    /// <summary>
    /// Oldest ready-to-dispatch webhook delivery timestamp, when any exist.
    /// </summary>
    public DateTimeOffset? OldestPendingAt { get; init; }

    /// <summary>
    /// Oldest failed webhook delivery timestamp, when any exist.
    /// </summary>
    public DateTimeOffset? OldestFailedAt { get; init; }
}
