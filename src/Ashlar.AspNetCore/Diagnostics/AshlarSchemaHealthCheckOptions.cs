using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Ashlar.AspNetCore.Diagnostics;

/// <summary>
/// Provides Ashlar schema health check options.
/// </summary>
public sealed class AshlarSchemaHealthCheckOptions
{
    /// <summary>
    /// Gets or sets the health status used when Ashlar schema diagnostics are not supported or not registered.
    /// </summary>
    public HealthStatus NotSupportedStatus { get; set; } = HealthStatus.Degraded;
}
