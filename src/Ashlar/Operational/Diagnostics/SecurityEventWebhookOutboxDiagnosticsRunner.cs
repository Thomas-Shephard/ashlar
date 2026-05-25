namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Provides shared security event webhook outbox diagnostics result mapping for Ashlar persistence providers.
/// </summary>
/// <param name="providerName">The provider name value.</param>
public sealed class SecurityEventWebhookOutboxDiagnosticsRunner(string providerName)
{
    private const string MissingTableReason = "Security event webhook outbox table has not been initialized.";
    private const string UnknownReason = "Security event webhook outbox diagnostics could not query provider state.";

    /// <summary>
    /// Checks provider security event webhook outbox state and returns a sanitized diagnostics result.
    /// </summary>
    /// <typeparam name="TConnection">The provider connection type.</typeparam>
    /// <param name="timeProvider">The time provider value.</param>
    /// <param name="context">The provider diagnostics context value.</param>
    /// <param name="options">The diagnostic options value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The diagnostic result.</returns>
    public async Task<SecurityEventWebhookOutboxDiagnosticResult> CheckAsync<TConnection>(
        TimeProvider timeProvider,
        SecurityEventWebhookOutboxDiagnosticsContext<TConnection> context,
        SecurityEventWebhookOutboxDiagnosticOptions options,
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
            new DiagnosticsQueryContext<TConnection, SecurityEventWebhookOutboxDiagnosticSnapshot>
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

    private SecurityEventWebhookOutboxDiagnosticResult CreateResult(
        AshlarDiagnosticStatus status,
        string? reason,
        DateTimeOffset checkedAt,
        SecurityEventWebhookOutboxDiagnosticOptions options,
        SecurityEventWebhookOutboxDiagnosticSnapshot? snapshot = null)
    {
        return new SecurityEventWebhookOutboxDiagnosticResult(
            status,
            providerName,
            reason,
            checkedAt,
            snapshot?.PendingCount,
            snapshot?.ScheduledCount,
            snapshot?.LockedCount,
            snapshot?.ExpiredLockCount,
            snapshot?.FailedCount,
            snapshot?.OldestPendingAt,
            snapshot?.OldestFailedAt,
            options.MaxAttempts,
            options.PollingInterval,
            options.BatchSize);
    }
}
