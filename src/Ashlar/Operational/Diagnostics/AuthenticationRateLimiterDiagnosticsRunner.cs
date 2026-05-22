namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Provides shared authentication rate limiter diagnostics result mapping for Ashlar providers.
/// </summary>
/// <param name="providerName">The provider name value.</param>
public sealed class AuthenticationRateLimiterDiagnosticsRunner(string providerName)
{
    private const string MissingTableReason = "Authentication rate limiter table has not been initialized.";
    private const string UnknownReason = "Authentication rate limiter diagnostics could not query provider state.";

    /// <summary>
    /// Checks provider authentication rate limiter state and returns a sanitized diagnostics result.
    /// </summary>
    /// <typeparam name="TConnection">The provider connection type.</typeparam>
    /// <param name="timeProvider">The time provider value.</param>
    /// <param name="context">The provider diagnostics context value.</param>
    /// <param name="options">The diagnostic options value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The diagnostic result.</returns>
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
            context.OpenConnectionAsync,
            context.TableExistsAsync,
            context.QuerySnapshotAsync,
            context.LogException,
            (status, reason, checkedAt, snapshot) => CreateResult(status, reason, checkedAt, options, snapshot),
            MissingTableReason,
            UnknownReason,
            cancellationToken);
    }

    /// <summary>
    /// Creates a diagnostics result from already available aggregate state.
    /// </summary>
    /// <param name="timeProvider">The time provider value.</param>
    /// <param name="options">The diagnostic options value.</param>
    /// <param name="snapshot">The snapshot value.</param>
    /// <returns>The diagnostic result.</returns>
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
