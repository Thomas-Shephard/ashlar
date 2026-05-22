namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Provides shared email outbox diagnostics result mapping for Ashlar persistence providers.
/// </summary>
/// <param name="providerName">The provider name value.</param>
public sealed class AshlarEmailOutboxDiagnosticsRunner(string providerName)
{
    private const string MissingTableReason = "Email outbox table has not been initialized.";
    private const string UnknownReason = "Email outbox diagnostics could not query provider state.";

    /// <summary>
    /// Checks provider email outbox state and returns a sanitized diagnostics result.
    /// </summary>
    /// <typeparam name="TConnection">The provider connection type.</typeparam>
    /// <param name="timeProvider">The time provider value.</param>
    /// <param name="context">The provider diagnostics context value.</param>
    /// <param name="options">The diagnostic options value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The diagnostic result.</returns>
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
            new DiagnosticsQueryContext<TConnection, EmailOutboxDiagnosticSnapshot, EmailOutboxDiagnosticResult>
            {
                OpenConnectionAsync = context.OpenConnectionAsync,
                TableExistsAsync = context.TableExistsAsync,
                QuerySnapshotAsync = context.QuerySnapshotAsync,
                LogException = context.LogException,
                CreateResult = (status, reason, checkedAt, snapshot) => CreateResult(status, reason, checkedAt, options, snapshot),
                MissingTableReason = MissingTableReason,
                UnknownReason = UnknownReason
            },
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
            snapshot?.OldestPendingAt,
            snapshot?.OldestFailedAt,
            options.MaxAttempts,
            options.PollingInterval,
            options.BatchSize);
    }
}
