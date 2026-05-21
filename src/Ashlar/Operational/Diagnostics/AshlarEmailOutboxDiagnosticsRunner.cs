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
    /// <param name="openConnectionAsync">The open connection callback.</param>
    /// <param name="tableExistsAsync">The table exists callback.</param>
    /// <param name="querySnapshotAsync">The snapshot query callback.</param>
    /// <param name="maxAttempts">The configured max attempts value.</param>
    /// <param name="pollingInterval">The configured polling interval value.</param>
    /// <param name="batchSize">The configured batch size value.</param>
    /// <param name="logException">The exception logging callback.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The diagnostic result.</returns>
    public async Task<EmailOutboxDiagnosticResult> CheckAsync<TConnection>(
        TimeProvider timeProvider,
        Func<CancellationToken, ValueTask<TConnection>> openConnectionAsync,
        Func<TConnection, CancellationToken, Task<bool>> tableExistsAsync,
        Func<TConnection, DateTimeOffset, CancellationToken, Task<EmailOutboxDiagnosticSnapshot>> querySnapshotAsync,
        int maxAttempts,
        TimeSpan pollingInterval,
        int batchSize,
        Action<Exception> logException,
        CancellationToken cancellationToken = default)
        where TConnection : IAsyncDisposable
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(openConnectionAsync);
        ArgumentNullException.ThrowIfNull(tableExistsAsync);
        ArgumentNullException.ThrowIfNull(querySnapshotAsync);
        ArgumentNullException.ThrowIfNull(logException);

        var checkedAt = timeProvider.GetUtcNow();
        EmailOutboxDiagnosticResult result;

        try
        {
            await using var connection = await openConnectionAsync(cancellationToken);
            if (!await tableExistsAsync(connection, cancellationToken))
            {
                result = CreateResult(AshlarDiagnosticStatus.NotSupported, MissingTableReason, checkedAt, maxAttempts, pollingInterval, batchSize);
            }
            else
            {
                var snapshot = await querySnapshotAsync(connection, checkedAt, cancellationToken);
                result = CreateResult(AshlarDiagnosticStatus.Healthy, null, checkedAt, maxAttempts, pollingInterval, batchSize, snapshot);
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            logException(ex);
            return CreateResult(AshlarDiagnosticStatus.Unknown, UnknownReason, checkedAt, maxAttempts, pollingInterval, batchSize);
        }

        return result;
    }

    private EmailOutboxDiagnosticResult CreateResult(
        AshlarDiagnosticStatus status,
        string? reason,
        DateTimeOffset checkedAt,
        int maxAttempts,
        TimeSpan pollingInterval,
        int batchSize,
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
            maxAttempts,
            pollingInterval,
            batchSize);
    }
}
