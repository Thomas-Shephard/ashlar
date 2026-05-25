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
        var status = AshlarOutboxHealthCheck.MapStatus(
            result.Status,
            ThresholdExceeded(result),
            _options.NotSupportedStatus,
            _options.ThresholdExceededStatus);

        return new HealthCheckResult(status, result.Reason, data: AshlarHealthCheckData.ForSecurityEventWebhookOutbox(result));
    }

    private bool ThresholdExceeded(SecurityEventWebhookOutboxDiagnosticResult result)
    {
        return AshlarOutboxHealthCheck.ThresholdExceeded(
            AshlarHealthCheckData.ToOutboxMetrics(result),
            new AshlarOutboxHealthCheckThresholds
            {
                FailedCountThreshold = _options.FailedCountThreshold,
                ExpiredLockCountThreshold = _options.ExpiredLockCountThreshold,
                PendingCountThreshold = _options.PendingCountThreshold,
                OldestPendingAgeThreshold = _options.OldestPendingAgeThreshold
            });
    }
}
