namespace Ashlar.AspNetCore.Diagnostics;

internal sealed record AshlarOutboxHealthCheckThresholds
{
    public long? FailedCountThreshold { get; init; }

    public long? ExpiredLockCountThreshold { get; init; }

    public long? PendingCountThreshold { get; init; }

    public TimeSpan? OldestPendingAgeThreshold { get; init; }
}
