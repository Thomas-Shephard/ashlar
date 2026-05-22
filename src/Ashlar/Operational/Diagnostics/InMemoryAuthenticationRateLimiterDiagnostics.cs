using Ashlar.Identity.RateLimiting;

namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Provides diagnostics for Ashlar's in-memory authentication rate limiter.
/// </summary>
/// <param name="rateLimiter">The rate limiter value.</param>
/// <param name="timeProvider">The time provider value.</param>
public sealed class InMemoryAuthenticationRateLimiterDiagnostics(
    InMemoryAuthenticationRateLimiter rateLimiter,
    TimeProvider timeProvider) : IAuthenticationRateLimiterDiagnostics
{
    private const string ProviderName = "InMemory";
    private static readonly AuthenticationRateLimiterDiagnosticsRunner DiagnosticsRunner = new(ProviderName);
    private static readonly AuthenticationRateLimiterDiagnosticOptions Options = new(
        true,
        false,
        false,
        false,
        null,
        null);

    private readonly InMemoryAuthenticationRateLimiter _rateLimiter = rateLimiter ?? throw new ArgumentNullException(nameof(rateLimiter));
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));

    /// <inheritdoc />
    public Task<AuthenticationRateLimiterDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        return Task.FromResult(DiagnosticsRunner.Healthy(
            _timeProvider,
            Options,
            new AuthenticationRateLimiterDiagnosticSnapshot
            {
                ActiveKeyCount = _rateLimiter.StateCount
            }));
    }
}
