using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Ashlar.AspNetCore.Diagnostics;

/// <summary>
/// Provides Ashlar rate limiter health check options.
/// </summary>
public sealed class AshlarRateLimiterHealthCheckOptions
{
    /// <summary>
    /// Gets or sets the health status used when Ashlar authentication rate limiter diagnostics are not supported or not registered.
    /// </summary>
    public HealthStatus NotSupportedStatus { get; set; } = HealthStatus.Degraded;
}
