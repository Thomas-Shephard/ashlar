using Ashlar.Operational.Diagnostics;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace Ashlar.AspNetCore.Diagnostics;

/// <summary>
/// Adapts Ashlar authentication rate limiter diagnostics to ASP.NET Core health checks.
/// </summary>
/// <param name="diagnostics">The authentication rate limiter diagnostics services.</param>
/// <param name="options">The authentication rate limiter health check options.</param>
public sealed class AshlarRateLimiterHealthCheck(
    IEnumerable<IAuthenticationRateLimiterDiagnostics> diagnostics,
    IOptions<AshlarRateLimiterHealthCheckOptions> options) : IHealthCheck
{
    private const string MissingDiagnosticsDescription = "Ashlar authentication rate limiter diagnostics are not registered.";
    private readonly IAuthenticationRateLimiterDiagnostics? _diagnostics = (diagnostics ?? throw new ArgumentNullException(nameof(diagnostics))).FirstOrDefault();
    private readonly AshlarRateLimiterHealthCheckOptions _options = options?.Value ?? throw new ArgumentNullException(nameof(options));

    /// <summary>
    /// Runs the Ashlar authentication rate limiter health check.
    /// </summary>
    /// <param name="context">The health check context.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The health check result.</returns>
    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        if (_diagnostics is null)
        {
            return new HealthCheckResult(_options.NotSupportedStatus, MissingDiagnosticsDescription);
        }

        var result = await _diagnostics.CheckAsync(cancellationToken);
        var status = result.Status switch
        {
            AshlarDiagnosticStatus.Healthy => HealthStatus.Healthy,
            AshlarDiagnosticStatus.NotSupported => _options.NotSupportedStatus,
            AshlarDiagnosticStatus.Unknown => HealthStatus.Unhealthy,
            AshlarDiagnosticStatus.Degraded => HealthStatus.Degraded,
            AshlarDiagnosticStatus.Unhealthy => HealthStatus.Unhealthy,
            _ => HealthStatus.Unhealthy
        };

        return new HealthCheckResult(status, result.Reason, data: AshlarHealthCheckData.ForRateLimiter(result));
    }
}
