namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Provides email outbox diagnostics for providers that do not support email outbox checks.
/// </summary>
/// <param name="providerName">The provider name value.</param>
/// <param name="timeProvider">The time provider value.</param>
public sealed class NotSupportedEmailOutboxDiagnostics(string providerName, TimeProvider timeProvider) : IEmailOutboxDiagnostics
{
    /// <inheritdoc />
    public Task<EmailOutboxDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult(new EmailOutboxDiagnosticResult(
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
