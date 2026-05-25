using Ashlar.Operational.Diagnostics;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Ashlar.AspNetCore.Diagnostics;

internal static class AshlarOutboxHealthCheck
{
    public static HealthStatus MapStatus(
        AshlarDiagnosticStatus diagnosticStatus,
        bool thresholdExceeded,
        HealthStatus notSupportedStatus,
        HealthStatus thresholdExceededStatus)
    {
        return diagnosticStatus switch
        {
            AshlarDiagnosticStatus.Healthy => thresholdExceeded ? thresholdExceededStatus : HealthStatus.Healthy,
            AshlarDiagnosticStatus.NotSupported => notSupportedStatus,
            AshlarDiagnosticStatus.Unknown => HealthStatus.Unhealthy,
            AshlarDiagnosticStatus.Degraded => HealthStatus.Degraded,
            AshlarDiagnosticStatus.Unhealthy => HealthStatus.Unhealthy,
            _ => HealthStatus.Unhealthy
        };
    }

    public static bool ThresholdExceeded(
        AshlarOutboxHealthCheckMetrics metrics,
        AshlarOutboxHealthCheckThresholds thresholds)
    {
        ArgumentNullException.ThrowIfNull(metrics);
        ArgumentNullException.ThrowIfNull(thresholds);

        return Exceeds(metrics.FailedCount, thresholds.FailedCountThreshold)
            || Exceeds(metrics.ExpiredLockCount, thresholds.ExpiredLockCountThreshold)
            || Exceeds(metrics.PendingCount, thresholds.PendingCountThreshold)
            || ExceedsOldestPendingAge(metrics, thresholds);
    }

    private static bool ExceedsOldestPendingAge(
        AshlarOutboxHealthCheckMetrics metrics,
        AshlarOutboxHealthCheckThresholds thresholds)
    {
        return thresholds.OldestPendingAgeThreshold.HasValue
            && metrics.OldestPendingAt.HasValue
            && metrics.CheckedAt - metrics.OldestPendingAt.Value > thresholds.OldestPendingAgeThreshold.Value;
    }

    private static bool Exceeds(long? value, long? threshold)
    {
        return value.HasValue && threshold.HasValue && value.Value > threshold.Value;
    }
}
