using Ashlar.Operational.Diagnostics;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace Ashlar.AspNetCore.Diagnostics;

/// <summary>
/// Adapts Ashlar schema diagnostics to ASP.NET Core health checks.
/// </summary>
/// <param name="diagnostics">The schema diagnostics services.</param>
/// <param name="options">The schema health check options.</param>
public sealed class AshlarSchemaHealthCheck(
    IEnumerable<IAshlarSchemaDiagnostics> diagnostics,
    IOptions<AshlarSchemaHealthCheckOptions> options) : IHealthCheck
{
    private const string MissingDiagnosticsDescription = "Ashlar schema diagnostics are not registered.";
    private readonly IAshlarSchemaDiagnostics? _diagnostics = (diagnostics ?? throw new ArgumentNullException(nameof(diagnostics))).FirstOrDefault();
    private readonly AshlarSchemaHealthCheckOptions _options = options?.Value ?? throw new ArgumentNullException(nameof(options));

    /// <summary>
    /// Runs the Ashlar schema health check.
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
            AshlarDiagnosticStatus.Healthy when result.SchemaStatus == AshlarSchemaStatus.Current => HealthStatus.Healthy,
            AshlarDiagnosticStatus.NotSupported => _options.NotSupportedStatus,
            AshlarDiagnosticStatus.Unknown => HealthStatus.Degraded,
            _ when result.SchemaStatus is AshlarSchemaStatus.NotInitialized or AshlarSchemaStatus.PendingMigrations => HealthStatus.Unhealthy,
            AshlarDiagnosticStatus.Degraded => HealthStatus.Degraded,
            AshlarDiagnosticStatus.Unhealthy => HealthStatus.Unhealthy,
            _ => HealthStatus.Degraded
        };

        return new HealthCheckResult(status, result.Reason, data: AshlarHealthCheckData.ForSchema(result));
    }
}
