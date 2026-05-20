namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Provides cleanup diagnostics for providers that do not support cleanup checks.
/// </summary>
/// <param name="providerName">The provider name value.</param>
/// <param name="timeProvider">The time provider value.</param>
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
