using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Ashlar.AspNetCore.Diagnostics;

/// <summary>
/// Provides Ashlar email outbox health check options.
/// </summary>
public sealed class AshlarEmailOutboxHealthCheckOptions
{
    /// <summary>
    /// Gets or sets the health status used when Ashlar email outbox diagnostics are not supported or not registered.
    /// </summary>
    public HealthStatus NotSupportedStatus { get; set; } = HealthStatus.Degraded;

    /// <summary>
    /// Gets or sets the status used when an email outbox threshold is exceeded.
    /// </summary>
    public HealthStatus ThresholdExceededStatus { get; set; } = HealthStatus.Degraded;

    /// <summary>
    /// Gets or sets the failed message count threshold.
    /// </summary>
    public long? FailedCountThreshold { get; set; }

    /// <summary>
    /// Gets or sets the expired lock count threshold.
    /// </summary>
    public long? ExpiredLockCountThreshold { get; set; }

    /// <summary>
    /// Gets or sets the pending message count threshold.
    /// </summary>
    public long? PendingCountThreshold { get; set; }

    /// <summary>
    /// Gets or sets the oldest pending message age threshold.
    /// </summary>
    public TimeSpan? OldestPendingAgeThreshold { get; set; }

    internal static bool Validate(AshlarEmailOutboxHealthCheckOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        return NonNegative(options.FailedCountThreshold)
            && NonNegative(options.ExpiredLockCountThreshold)
            && NonNegative(options.PendingCountThreshold)
            && (!options.OldestPendingAgeThreshold.HasValue || options.OldestPendingAgeThreshold.Value > TimeSpan.Zero);
    }

    private static bool NonNegative(long? value)
    {
        return !value.HasValue || value.Value >= 0;
    }
}
