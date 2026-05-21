using Microsoft.Extensions.Options;

namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Provides cleanup diagnostics from configured Ashlar cleanup options.
/// </summary>
/// <param name="providerName">The provider name value.</param>
/// <param name="options">The cleanup options value.</param>
/// <param name="timeProvider">The time provider value.</param>
public abstract class AshlarCleanupDiagnostics(
    string providerName,
    IOptions<AshlarCleanupOptions> options,
    TimeProvider timeProvider) : IAshlarCleanupDiagnostics
{
    private readonly AshlarCleanupDiagnosticsRunner _diagnosticsRunner = new(providerName);
    private readonly IOptions<AshlarCleanupOptions> _options = options ?? throw new ArgumentNullException(nameof(options));
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));

    /// <inheritdoc />
    public Task<AshlarCleanupDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(_diagnosticsRunner.Check(_timeProvider, _options.Value, configured: true));
    }
}
