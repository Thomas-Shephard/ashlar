namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Provides cleanup diagnostics for providers that do not support cleanup checks.
/// </summary>
/// <param name="providerName">Provider name reported in the not-supported diagnostic result.</param>
/// <param name="timeProvider">Clock used to stamp diagnostic results.</param>
public sealed class NotSupportedAshlarCleanupDiagnostics(string providerName, TimeProvider timeProvider) : IAshlarCleanupDiagnostics
{
    /// <inheritdoc />
    public Task<AshlarCleanupDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult(new AshlarCleanupDiagnosticResult(
            AshlarDiagnosticStatus.NotSupported,
            providerName,
            null,
            timeProvider.GetUtcNow(),
            false,
            false,
            null,
            null,
            null,
            null,
            null));
    }
}
