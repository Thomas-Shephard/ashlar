namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Defines provider-neutral diagnostics for Ashlar authentication rate limiting.
/// </summary>
public interface IAuthenticationRateLimiterDiagnostics
{
    /// <summary>
    /// Checks the Ashlar authentication rate limiter state.
    /// </summary>
    /// <param name="cancellationToken">Token for aborting diagnostics work.</param>
    /// <returns>Provider-neutral rate limiter diagnostic result.</returns>
    Task<AuthenticationRateLimiterDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default);
}
