namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Provides shared security event webhook outbox diagnostics result mapping for Ashlar persistence providers.
/// </summary>
/// <param name="providerName">Persistence provider name reported in diagnostic results.</param>
public sealed class SecurityEventWebhookOutboxDiagnosticsRunner(string providerName)
{
    private const string MissingTableReason = "Security event webhook outbox table has not been initialized.";
    private const string UnknownReason = "Security event webhook outbox diagnostics could not query provider state.";

    /// <summary>
    /// Checks provider security event webhook outbox state and returns a sanitized diagnostics result.
    /// </summary>
    /// <typeparam name="TConnection">Provider connection type used by diagnostics queries.</typeparam>
    /// <param name="timeProvider">Clock used to stamp the diagnostic result.</param>
    /// <param name="context">Provider callbacks used to query aggregate webhook outbox state.</param>
    /// <param name="options">Configured webhook dispatcher settings to surface in the result.</param>
    /// <param name="cancellationToken">Token for aborting provider diagnostics work.</param>
    /// <returns>Provider-neutral webhook outbox diagnostic result with aggregate counts only.</returns>
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
