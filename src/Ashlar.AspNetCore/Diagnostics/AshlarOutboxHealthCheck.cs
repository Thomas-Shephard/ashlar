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
        long? failedCount,
        long? failedCountThreshold,
        long? expiredLockCount,
        long? expiredLockCountThreshold,
        long? pendingCount,
        long? pendingCountThreshold,
        DateTimeOffset checkedAt,
        DateTimeOffset? oldestPendingAt,
        TimeSpan? oldestPendingAgeThreshold)
    {
        return Exceeds(failedCount, failedCountThreshold)
            || Exceeds(expiredLockCount, expiredLockCountThreshold)
            || Exceeds(pendingCount, pendingCountThreshold)
            || ExceedsOldestPendingAge(checkedAt, oldestPendingAt, oldestPendingAgeThreshold);
    }

    private static bool ExceedsOldestPendingAge(
        DateTimeOffset checkedAt,
        DateTimeOffset? oldestPendingAt,
        TimeSpan? oldestPendingAgeThreshold)
    {
        return oldestPendingAgeThreshold.HasValue
            && oldestPendingAt.HasValue
            && checkedAt - oldestPendingAt.Value > oldestPendingAgeThreshold.Value;
    }

    private static bool Exceeds(long? value, long? threshold)
    {
        return value.HasValue && threshold.HasValue && value.Value > threshold.Value;
    }
}
