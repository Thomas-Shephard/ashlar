namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Defines provider-neutral diagnostics for the Ashlar email outbox.
/// </summary>
public interface IEmailOutboxDiagnostics
{
    /// <summary>
    /// Checks the Ashlar email outbox state.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The diagnostic result.</returns>
    Task<EmailOutboxDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default);
}
