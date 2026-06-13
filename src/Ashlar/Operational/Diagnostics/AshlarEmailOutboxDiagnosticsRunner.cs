namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Provides shared email outbox diagnostics result mapping for Ashlar persistence providers.
/// </summary>
/// <param name="providerName">Persistence provider name reported in diagnostic results.</param>
public sealed class AshlarEmailOutboxDiagnosticsRunner(string providerName)
{
    private const string MissingTableReason = "Email outbox table has not been initialized.";
    private const string UnknownReason = "Email outbox diagnostics could not query provider state.";

    /// <summary>
    /// Checks provider email outbox state and returns a sanitized diagnostics result.
    /// </summary>
    /// <typeparam name="TConnection">Provider connection type used by diagnostics queries.</typeparam>
    /// <param name="timeProvider">Clock used to stamp the diagnostic result.</param>
    /// <param name="context">Provider callbacks used to query aggregate outbox state.</param>
    /// <param name="options">Configured outbox dispatcher settings to surface in the result.</param>
    /// <param name="cancellationToken">Token for aborting provider diagnostics work.</param>
    /// <returns>Provider-neutral outbox diagnostic result with aggregate counts only.</returns>
    public async Task<EmailOutboxDiagnosticResult> CheckAsync<TConnection>(
        TimeProvider timeProvider,
        EmailOutboxDiagnosticsContext<TConnection> context,
        EmailOutboxDiagnosticOptions options,
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
            new DiagnosticsQueryContext<TConnection, EmailOutboxDiagnosticSnapshot>
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

    private EmailOutboxDiagnosticResult CreateResult(
        AshlarDiagnosticStatus status,
        string? reason,
        DateTimeOffset checkedAt,
        EmailOutboxDiagnosticOptions options,
        EmailOutboxDiagnosticSnapshot? snapshot = null)
    {
        return new EmailOutboxDiagnosticResult(
            status,
            providerName,
            reason,
            checkedAt,
            snapshot?.PendingCount,
            snapshot?.ScheduledCount,
            snapshot?.LockedCount,
            snapshot?.ExpiredLockCount,
            snapshot?.FailedCount,
            snapshot?.SensitivePendingCount,
            snapshot?.SensitiveScheduledCount,
            snapshot?.SensitiveLockedCount,
            snapshot?.SensitiveFailedCount,
            snapshot?.OldestPendingAt,
            snapshot?.OldestFailedAt,
            options.MaxAttempts,
            options.PollingInterval,
            options.BatchSize);
    }
}
