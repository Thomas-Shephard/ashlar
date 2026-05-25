using Ashlar.Operational.Diagnostics;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace Ashlar.AspNetCore.Diagnostics;

/// <summary>
/// Adapts Ashlar email outbox diagnostics to ASP.NET Core health checks.
/// </summary>
/// <param name="diagnostics">The email outbox diagnostics services.</param>
/// <param name="options">The email outbox health check options.</param>
public sealed class AshlarEmailOutboxHealthCheck(
    IEnumerable<IEmailOutboxDiagnostics> diagnostics,
    IOptions<AshlarEmailOutboxHealthCheckOptions> options) : IHealthCheck
{
    private const string MissingDiagnosticsDescription = "Ashlar email outbox diagnostics are not registered.";
    private readonly IEmailOutboxDiagnostics? _diagnostics = (diagnostics ?? throw new ArgumentNullException(nameof(diagnostics))).FirstOrDefault();
    private readonly AshlarEmailOutboxHealthCheckOptions _options = options?.Value ?? throw new ArgumentNullException(nameof(options));

    /// <summary>
    /// Runs the Ashlar email outbox health check.
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

        return new HealthCheckResult(status, result.Reason, data: AshlarHealthCheckData.ForEmailOutbox(result));
    }

    private bool ThresholdExceeded(EmailOutboxDiagnosticResult result)
    {
        return AshlarOutboxHealthCheck.ThresholdExceeded(
            result.FailedCount,
            _options.FailedCountThreshold,
            result.ExpiredLockCount,
            _options.ExpiredLockCountThreshold,
            result.PendingCount,
            _options.PendingCountThreshold,
            result.CheckedAt,
            result.OldestPendingAt,
            _options.OldestPendingAgeThreshold);
    }
}
