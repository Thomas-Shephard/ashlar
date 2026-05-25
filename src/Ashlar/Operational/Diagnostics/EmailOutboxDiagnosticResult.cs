namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Represents a provider-neutral diagnostic result for the Ashlar email outbox.
/// </summary>
/// <param name="Status">The diagnostic status value.</param>
/// <param name="ProviderName">The provider name value.</param>
/// <param name="Reason">The reason value.</param>
/// <param name="CheckedAt">The checked at value.</param>
/// <param name="PendingCount">The pending count value.</param>
/// <param name="ScheduledCount">The scheduled count value.</param>
/// <param name="LockedCount">The locked count value.</param>
/// <param name="ExpiredLockCount">The expired lock count value.</param>
/// <param name="FailedCount">The failed count value.</param>
/// <param name="SensitivePendingCount">The sensitive pending count value.</param>
/// <param name="SensitiveScheduledCount">The sensitive scheduled count value.</param>
/// <param name="SensitiveLockedCount">The sensitive locked count value.</param>
/// <param name="SensitiveFailedCount">The sensitive failed count value.</param>
/// <param name="OldestPendingAt">The oldest pending at value.</param>
/// <param name="OldestFailedAt">The oldest failed at value.</param>
/// <param name="MaxAttempts">The max attempts value.</param>
/// <param name="PollingInterval">The polling interval value.</param>
/// <param name="BatchSize">The batch size value.</param>
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
