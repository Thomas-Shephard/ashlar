namespace Ashlar.Operational.Diagnostics;

internal static class DiagnosticsQueryRunner
{
    public static async Task<TResult> CheckAsync<TConnection, TSnapshot, TResult>(
        TimeProvider timeProvider,
        Func<CancellationToken, ValueTask<TConnection>> openConnectionAsync,
        Func<TConnection, CancellationToken, Task<bool>> tableExistsAsync,
        Func<TConnection, DateTimeOffset, CancellationToken, Task<TSnapshot>> querySnapshotAsync,
        Action<Exception> logException,
        Func<AshlarDiagnosticStatus, string?, DateTimeOffset, TSnapshot?, TResult> createResult,
        string missingTableReason,
        string unknownReason,
        CancellationToken cancellationToken)
        where TConnection : IAsyncDisposable
    {
        var checkedAt = timeProvider.GetUtcNow();

        try
        {
            await using var connection = await openConnectionAsync(cancellationToken);
            if (!await tableExistsAsync(connection, cancellationToken))
            {
                return createResult(AshlarDiagnosticStatus.NotSupported, missingTableReason, checkedAt, default);
            }

            var snapshot = await querySnapshotAsync(connection, checkedAt, cancellationToken);
            return createResult(AshlarDiagnosticStatus.Healthy, null, checkedAt, snapshot);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            logException(ex);
            return createResult(AshlarDiagnosticStatus.Unknown, unknownReason, checkedAt, default);
        }
    }
}
