namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Provides shared authentication rate limiter diagnostics plumbing for Ashlar providers.
/// </summary>
/// <typeparam name="TConnection">Provider connection type used by diagnostics queries.</typeparam>
/// <param name="providerName">Persistence provider name reported in diagnostic results.</param>
/// <param name="timeProvider">Clock used to stamp diagnostic results.</param>
public abstract class AuthenticationRateLimiterDiagnostics<TConnection>(
    string providerName,
    TimeProvider timeProvider) : IAuthenticationRateLimiterDiagnostics
    where TConnection : IAsyncDisposable
{
    private readonly AuthenticationRateLimiterDiagnosticsRunner _diagnosticsRunner = new(providerName);
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));

    /// <inheritdoc />
    public async Task<AuthenticationRateLimiterDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default)
    {
        return await _diagnosticsRunner.CheckAsync(
            _timeProvider,
            new AuthenticationRateLimiterDiagnosticsContext<TConnection>(
                OpenConnectionAsync,
                TableExistsAsync,
                QuerySnapshotAsync,
                LogException),
            CreateOptions(),
            cancellationToken);
    }

    /// <summary>
    /// Opens a provider connection.
    /// </summary>
    /// <param name="cancellationToken">Token for aborting provider connection work.</param>
    /// <returns>Open provider connection for diagnostics queries.</returns>
    protected abstract ValueTask<TConnection> OpenConnectionAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Checks whether the provider rate limiter table exists.
    /// </summary>
    /// <param name="connection">Open provider connection to inspect.</param>
    /// <param name="cancellationToken">Token for aborting table inspection.</param>
    /// <returns><see langword="true" /> when the table exists; otherwise, <see langword="false" />.</returns>
    protected abstract Task<bool> TableExistsAsync(TConnection connection, CancellationToken cancellationToken);

    /// <summary>
    /// Queries safe aggregate rate limiter state.
    /// </summary>
    /// <param name="connection">Open provider connection to inspect.</param>
    /// <param name="now">Current UTC time used to classify expired limiter entries.</param>
    /// <param name="cancellationToken">Token for aborting aggregate snapshot queries.</param>
    /// <returns>Aggregate limiter counts that do not expose raw rate-limit keys.</returns>
    protected abstract Task<AuthenticationRateLimiterDiagnosticSnapshot> QuerySnapshotAsync(
        TConnection connection,
        DateTimeOffset now,
        CancellationToken cancellationToken);

    /// <summary>
    /// Creates provider capability and cleanup options.
    /// </summary>
    /// <returns>Provider capability and cleanup options reported by diagnostics.</returns>
    protected abstract AuthenticationRateLimiterDiagnosticOptions CreateOptions();

    /// <summary>
    /// Logs a provider diagnostics exception safely.
    /// </summary>
    /// <param name="exception">Provider exception to log without exposing rate-limit keys.</param>
    protected abstract void LogException(Exception exception);
}
