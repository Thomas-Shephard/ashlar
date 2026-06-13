namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Defines provider-neutral diagnostics for the Ashlar email outbox.
/// </summary>
public interface IEmailOutboxDiagnostics
{
    /// <summary>
    /// Checks the Ashlar email outbox state.
    /// </summary>
    /// <param name="cancellationToken">Token for aborting diagnostics work.</param>
    /// <returns>Provider-neutral email outbox diagnostic result with aggregate counts only.</returns>
    Task<EmailOutboxDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default);
}
