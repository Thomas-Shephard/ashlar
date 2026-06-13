namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Provides shared authentication rate limiter diagnostics result mapping for Ashlar providers.
/// </summary>
/// <param name="providerName">Persistence provider name reported in diagnostic results.</param>
public sealed class AuthenticationRateLimiterDiagnosticsRunner(string providerName)
{
    private const string MissingTableReason = "Authentication rate limiter table has not been initialized.";
    private const string UnknownReason = "Authentication rate limiter diagnostics could not query provider state.";

    /// <summary>
    /// Checks provider authentication rate limiter state and returns a sanitized diagnostics result.
    /// </summary>
    /// <typeparam name="TConnection">Provider connection type used by diagnostics queries.</typeparam>
    /// <param name="timeProvider">Clock used to stamp the diagnostic result.</param>
    /// <param name="context">Provider callbacks used to query aggregate limiter state.</param>
    /// <param name="options">Provider capability and cleanup settings to surface in the result.</param>
    /// <param name="cancellationToken">Token for aborting provider diagnostics work.</param>
    /// <returns>Provider-neutral rate limiter diagnostic result with aggregate counts only.</returns>
    public async Task<AuthenticationRateLimiterDiagnosticResult> CheckAsync<TConnection>(
        TimeProvider timeProvider,
        AuthenticationRateLimiterDiagnosticsContext<TConnection> context,
        AuthenticationRateLimiterDiagnosticOptions options,
        CancellationToken cancellationToken = default)
        where TConnection : IAsyncDisposable
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(context.OpenConnectionAsync);
        ArgumentNullException.ThrowIfNull(context.TableExistsAsync);
        ArgumentNullException.ThrowIfNull(context.QuerySnapshotAsync);
        ArgumentNullException.ThrowIfNull(context.LogException);
        ArgumentNullException.ThrowIfNull(options);

        return await DiagnosticsQueryRunner.CheckAsync(
            timeProvider,
            new DiagnosticsQueryContext<TConnection, AuthenticationRateLimiterDiagnosticSnapshot>
            {
                OpenConnectionAsync = context.OpenConnectionAsync,
                TableExistsAsync = context.TableExistsAsync,
                QuerySnapshotAsync = context.QuerySnapshotAsync,
                LogException = context.LogException,
                MissingTableReason = MissingTableReason,
                UnknownReason = UnknownReason
            },
            (status, reason, checkedAt, snapshot) => CreateResult(status, reason, checkedAt, options, snapshot),
            cancellationToken);
    }

    /// <summary>
    /// Creates a diagnostics result from already available aggregate state.
    /// </summary>
    /// <param name="timeProvider">Clock used to stamp the diagnostic result.</param>
    /// <param name="options">Provider capability and cleanup settings to surface in the result.</param>
    /// <param name="snapshot">Safe aggregate limiter state.</param>
    /// <returns>Healthy provider-neutral rate limiter diagnostic result.</returns>
    public AuthenticationRateLimiterDiagnosticResult Healthy(
        TimeProvider timeProvider,
        AuthenticationRateLimiterDiagnosticOptions options,
        AuthenticationRateLimiterDiagnosticSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(snapshot);

        return CreateResult(AshlarDiagnosticStatus.Healthy, null, timeProvider.GetUtcNow(), options, snapshot);
    }

    private AuthenticationRateLimiterDiagnosticResult CreateResult(
        AshlarDiagnosticStatus status,
        string? reason,
        DateTimeOffset checkedAt,
        AuthenticationRateLimiterDiagnosticOptions options,
        AuthenticationRateLimiterDiagnosticSnapshot? snapshot = null)
    {
        return new AuthenticationRateLimiterDiagnosticResult(
            status,
            providerName,
            reason,
            checkedAt,
            options.Configured,
            options.Distributed,
            options.Persistent,
            snapshot?.ExpiredRowCount,
            snapshot?.ActiveKeyCount,
            snapshot?.BlockedKeyCount,
            options.CleanupConfigured,
            options.CleanupInterval,
            options.MaxCleanupRows);
    }
}
