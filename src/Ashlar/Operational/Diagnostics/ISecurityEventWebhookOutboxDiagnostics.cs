namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Defines provider-neutral diagnostics for the Ashlar security event webhook outbox.
/// </summary>
public interface ISecurityEventWebhookOutboxDiagnostics
{
    /// <summary>
    /// Checks the Ashlar security event webhook outbox state.
    /// </summary>
    /// <param name="cancellationToken">Token for aborting diagnostics work.</param>
    /// <returns>Provider-neutral webhook outbox diagnostic result with aggregate counts only.</returns>
    Task<SecurityEventWebhookOutboxDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default);
}
