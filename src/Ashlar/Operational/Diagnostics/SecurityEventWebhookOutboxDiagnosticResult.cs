namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Describes aggregate diagnostic state for the Ashlar security event webhook outbox.
/// </summary>
/// <param name="Status">Overall diagnostic status for the webhook outbox check.</param>
/// <param name="ProviderName">Persistence provider that produced the diagnostic result.</param>
/// <param name="Reason">Optional provider-safe reason when the check is unavailable, degraded, or failed.</param>
/// <param name="CheckedAt">UTC time when the diagnostic check completed.</param>
/// <param name="PendingCount">Number of webhook deliveries ready to send.</param>
/// <param name="ScheduledCount">Number of webhook deliveries scheduled for retry or future delivery.</param>
/// <param name="LockedCount">Number of webhook deliveries currently locked by a dispatcher.</param>
/// <param name="ExpiredLockCount">Number of locked webhook deliveries whose lock has expired.</param>
/// <param name="FailedCount">Number of webhook deliveries that exhausted delivery attempts.</param>
/// <param name="OldestPendingAt">Oldest pending webhook delivery timestamp, when available.</param>
/// <param name="OldestFailedAt">Oldest failed webhook delivery timestamp, when available.</param>
/// <param name="MaxAttempts">Configured maximum delivery attempts.</param>
/// <param name="PollingInterval">Configured dispatcher polling interval.</param>
/// <param name="BatchSize">Configured dispatcher batch size.</param>
public sealed record SecurityEventWebhookOutboxDiagnosticResult(
    AshlarDiagnosticStatus Status,
    string ProviderName,
    string? Reason,
    DateTimeOffset CheckedAt,
    long? PendingCount,
    long? ScheduledCount,
    long? LockedCount,
    long? ExpiredLockCount,
    long? FailedCount,
    DateTimeOffset? OldestPendingAt,
    DateTimeOffset? OldestFailedAt,
    int? MaxAttempts,
    TimeSpan? PollingInterval,
    int? BatchSize);
