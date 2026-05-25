using Ashlar.Operational.Diagnostics;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace Ashlar.AspNetCore.Diagnostics;

/// <summary>
/// Adapts Ashlar security event webhook outbox diagnostics to ASP.NET Core health checks.
/// </summary>
/// <param name="diagnostics">The security event webhook outbox diagnostics services.</param>
/// <param name="options">The security event webhook outbox health check options.</param>
public sealed class AshlarSecurityEventWebhookOutboxHealthCheck(
    IEnumerable<ISecurityEventWebhookOutboxDiagnostics> diagnostics,
    IOptions<AshlarSecurityEventWebhookOutboxHealthCheckOptions> options) : IHealthCheck
{
    private const string MissingDiagnosticsDescription = "Ashlar security event webhook outbox diagnostics are not registered.";
    private readonly ISecurityEventWebhookOutboxDiagnostics? _diagnostics = (diagnostics ?? throw new ArgumentNullException(nameof(diagnostics))).FirstOrDefault();
    private readonly AshlarSecurityEventWebhookOutboxHealthCheckOptions _options = options?.Value ?? throw new ArgumentNullException(nameof(options));

    /// <summary>
    /// Runs the Ashlar security event webhook outbox health check.
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
            AshlarDiagnosticStatus.Healthy => ThresholdExceeded(result) ? _options.ThresholdExceededStatus : HealthStatus.Healthy,
            AshlarDiagnosticStatus.NotSupported => _options.NotSupportedStatus,
            AshlarDiagnosticStatus.Unknown => HealthStatus.Unhealthy,
            AshlarDiagnosticStatus.Degraded => HealthStatus.Degraded,
            AshlarDiagnosticStatus.Unhealthy => HealthStatus.Unhealthy,
            _ => HealthStatus.Unhealthy
        };

        return new HealthCheckResult(status, result.Reason, data: AshlarHealthCheckData.ForSecurityEventWebhookOutbox(result));
    }

    private bool ThresholdExceeded(SecurityEventWebhookOutboxDiagnosticResult result)
    {
        return Exceeds(result.FailedCount, _options.FailedCountThreshold)
            || Exceeds(result.ExpiredLockCount, _options.ExpiredLockCountThreshold)
            || ExceedsOldestPendingAge(result);
    }

    private bool ExceedsOldestPendingAge(SecurityEventWebhookOutboxDiagnosticResult result)
    {
        return _options.OldestPendingAgeThreshold.HasValue
            && result.OldestPendingAt.HasValue
            && result.CheckedAt - result.OldestPendingAt.Value > _options.OldestPendingAgeThreshold.Value;
    }

    private static bool Exceeds(long? value, long? threshold)
    {
        return value.HasValue && threshold.HasValue && value.Value > threshold.Value;
    }
}
