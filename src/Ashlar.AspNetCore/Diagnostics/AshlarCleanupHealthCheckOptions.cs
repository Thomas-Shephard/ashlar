using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Ashlar.AspNetCore.Diagnostics;

/// <summary>
/// Provides Ashlar cleanup health check options.
/// </summary>
public sealed class AshlarCleanupHealthCheckOptions
{
    /// <summary>
    /// Gets or sets the health status used when Ashlar cleanup diagnostics are not supported or not registered.
    /// </summary>
    public HealthStatus NotSupportedStatus { get; set; } = HealthStatus.Degraded;
}
