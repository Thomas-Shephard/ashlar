using Ashlar.Operational.Diagnostics;

namespace Ashlar.AspNetCore.Diagnostics;

internal sealed record AshlarOutboxHealthCheckMetrics
{
    public AshlarDiagnosticStatus Status { get; init; }

    public string ProviderName { get; init; } = string.Empty;

    public string? Reason { get; init; }

    public DateTimeOffset CheckedAt { get; init; }

    public long? PendingCount { get; init; }

    public long? ScheduledCount { get; init; }

    public long? LockedCount { get; init; }

    public long? ExpiredLockCount { get; init; }

    public long? FailedCount { get; init; }

    public DateTimeOffset? OldestPendingAt { get; init; }

    public DateTimeOffset? OldestFailedAt { get; init; }

    public int? MaxAttempts { get; init; }

    public TimeSpan? PollingInterval { get; init; }

    public int? BatchSize { get; init; }
}
