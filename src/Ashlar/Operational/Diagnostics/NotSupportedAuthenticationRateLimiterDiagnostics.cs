namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Provides authentication rate limiter diagnostics for providers that do not support rate limiter checks.
/// </summary>
/// <param name="providerName">The provider name value.</param>
/// <param name="timeProvider">The time provider value.</param>
public sealed class NotSupportedAuthenticationRateLimiterDiagnostics(string providerName, TimeProvider timeProvider) : IAuthenticationRateLimiterDiagnostics
{
    /// <inheritdoc />
    public Task<AuthenticationRateLimiterDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult(new AuthenticationRateLimiterDiagnosticResult(
            AshlarDiagnosticStatus.NotSupported,
            providerName,
            null,
            timeProvider.GetUtcNow(),
            false,
            false,
            false,
            null,
            null,
            null,
            null,
            null,
            null));
    }
}
