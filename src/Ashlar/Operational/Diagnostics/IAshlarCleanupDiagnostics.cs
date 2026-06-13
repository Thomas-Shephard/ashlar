namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Defines provider-neutral diagnostics for Ashlar cleanup configuration.
/// </summary>
public interface IAshlarCleanupDiagnostics
{
    /// <summary>
    /// Checks the Ashlar cleanup configuration.
    /// </summary>
    /// <param name="cancellationToken">Token for aborting diagnostics work.</param>
    /// <returns>Provider-neutral cleanup diagnostic result.</returns>
    Task<AshlarCleanupDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default);
}
