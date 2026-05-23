using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Ashlar.AspNetCore.Diagnostics;

/// <summary>
/// Provides common Ashlar health check options.
/// </summary>
public class AshlarHealthCheckOptions
{
    /// <summary>
    /// Gets or sets the health status used when the underlying Ashlar diagnostic is not supported.
    /// </summary>
    public HealthStatus NotSupportedStatus { get; set; } = HealthStatus.Degraded;
}

/// <summary>
/// Provides Ashlar schema health check options.
/// </summary>
public sealed class AshlarSchemaHealthCheckOptions : AshlarHealthCheckOptions;

/// <summary>
/// Provides Ashlar cleanup health check options.
/// </summary>
public sealed class AshlarCleanupHealthCheckOptions : AshlarHealthCheckOptions;

/// <summary>
/// Provides Ashlar rate limiter health check options.
/// </summary>
public sealed class AshlarRateLimiterHealthCheckOptions : AshlarHealthCheckOptions;
