namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Provides a schema diagnostics implementation for providers that do not support schema checks.
/// </summary>
/// <param name="providerName">The provider name value.</param>
/// <param name="timeProvider">The time provider value.</param>
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
