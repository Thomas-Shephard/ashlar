namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Defines provider-neutral diagnostics for the Ashlar security event webhook outbox.
/// </summary>
public interface ISecurityEventWebhookOutboxDiagnostics
{
    /// <summary>
    /// Checks the Ashlar security event webhook outbox state.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The diagnostic result.</returns>
    Task<SecurityEventWebhookOutboxDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default);
}
