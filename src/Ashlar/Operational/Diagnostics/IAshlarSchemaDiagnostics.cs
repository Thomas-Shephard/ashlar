namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Defines provider-neutral diagnostics for Ashlar storage schema state.
/// </summary>
public interface IAshlarSchemaDiagnostics
{
    /// <summary>
    /// Checks the Ashlar schema state.
    /// </summary>
    /// <param name="cancellationToken">Token for aborting diagnostics work.</param>
    /// <returns>Provider-neutral schema diagnostic result.</returns>
    Task<AshlarSchemaDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default);
}
