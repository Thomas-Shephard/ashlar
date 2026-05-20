namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Defines provider-neutral diagnostics for Ashlar cleanup configuration.
/// </summary>
public interface IAshlarCleanupDiagnostics
{
    /// <summary>
    /// Checks the Ashlar cleanup configuration.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The diagnostic result.</returns>
    Task<AshlarCleanupDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default);
}
