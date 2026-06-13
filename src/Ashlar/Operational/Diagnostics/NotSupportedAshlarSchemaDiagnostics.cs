namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Provides a schema diagnostics implementation for providers that do not support schema checks.
/// </summary>
/// <param name="providerName">Provider name reported in the not-supported diagnostic result.</param>
/// <param name="timeProvider">Clock used to stamp diagnostic results.</param>
public sealed class NotSupportedAshlarSchemaDiagnostics(string providerName, TimeProvider timeProvider) : IAshlarSchemaDiagnostics
{
    /// <inheritdoc />
    public Task<AshlarSchemaDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult(new AshlarSchemaDiagnosticResult(
            AshlarDiagnosticStatus.NotSupported,
            providerName,
            null,
            timeProvider.GetUtcNow(),
            AshlarSchemaStatus.Unknown,
            null,
            null,
            null,
            null,
            null,
            null,
            null));
    }
}
