using Ashlar.Operational.Diagnostics;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace Ashlar.AspNetCore.Diagnostics;

/// <summary>
/// Adapts Ashlar cleanup diagnostics to ASP.NET Core health checks.
/// </summary>
/// <param name="diagnostics">The cleanup diagnostics services.</param>
/// <param name="options">The cleanup health check options.</param>
public sealed class AshlarCleanupHealthCheck(
    IEnumerable<IAshlarCleanupDiagnostics> diagnostics,
    IOptions<AshlarCleanupHealthCheckOptions> options) : IHealthCheck
{
    private const string MissingDiagnosticsDescription = "Ashlar cleanup diagnostics are not registered.";
    private readonly IAshlarCleanupDiagnostics? _diagnostics = (diagnostics ?? throw new ArgumentNullException(nameof(diagnostics))).FirstOrDefault();
    private readonly AshlarCleanupHealthCheckOptions _options = options?.Value ?? throw new ArgumentNullException(nameof(options));

    /// <summary>
    /// Runs the Ashlar cleanup health check.
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
            AshlarDiagnosticStatus.Healthy when result.OptionsValid => HealthStatus.Healthy,
            AshlarDiagnosticStatus.NotSupported => _options.NotSupportedStatus,
            AshlarDiagnosticStatus.Unhealthy => HealthStatus.Unhealthy,
            AshlarDiagnosticStatus.Unknown => HealthStatus.Unhealthy,
            AshlarDiagnosticStatus.Degraded => HealthStatus.Degraded,
            _ when !result.Configured => _options.NotSupportedStatus,
            _ when !result.OptionsValid => HealthStatus.Unhealthy,
            _ => HealthStatus.Degraded
        };

        return new HealthCheckResult(status, result.Reason, data: AshlarHealthCheckData.ForCleanup(result));
    }
}
