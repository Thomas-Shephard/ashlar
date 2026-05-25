namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Provides security event webhook outbox diagnostics for providers that do not support security event webhook outbox checks.
/// </summary>
/// <param name="providerName">The provider name value.</param>
/// <param name="timeProvider">The time provider value.</param>
public sealed class NotSupportedSecurityEventWebhookOutboxDiagnostics(string providerName, TimeProvider timeProvider) : ISecurityEventWebhookOutboxDiagnostics
{
    /// <inheritdoc />
    public Task<SecurityEventWebhookOutboxDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult(new SecurityEventWebhookOutboxDiagnosticResult(
            AshlarDiagnosticStatus.NotSupported,
            providerName,
            null,
            timeProvider.GetUtcNow(),
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null));
    }
}
