namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Provides shared authentication rate limiter diagnostics plumbing for Ashlar providers.
/// </summary>
/// <typeparam name="TConnection">The provider connection type.</typeparam>
/// <param name="providerName">The provider name value.</param>
/// <param name="timeProvider">The time provider value.</param>
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
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The provider connection.</returns>
    protected abstract ValueTask<TConnection> OpenConnectionAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Checks whether the provider rate limiter table exists.
    /// </summary>
    /// <param name="connection">The provider connection value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns><see langword="true" /> when the table exists; otherwise, <see langword="false" />.</returns>
    protected abstract Task<bool> TableExistsAsync(TConnection connection, CancellationToken cancellationToken);

    /// <summary>
    /// Queries safe aggregate rate limiter state.
    /// </summary>
    /// <param name="connection">The provider connection value.</param>
    /// <param name="now">The current timestamp value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The safe aggregate snapshot.</returns>
    protected abstract Task<AuthenticationRateLimiterDiagnosticSnapshot> QuerySnapshotAsync(
        TConnection connection,
        DateTimeOffset now,
        CancellationToken cancellationToken);

    /// <summary>
    /// Creates provider capability and cleanup options.
    /// </summary>
    /// <returns>The diagnostic options.</returns>
    protected abstract AuthenticationRateLimiterDiagnosticOptions CreateOptions();

    /// <summary>
    /// Logs a provider diagnostics exception safely.
    /// </summary>
    /// <param name="exception">The exception value.</param>
    protected abstract void LogException(Exception exception);
}
