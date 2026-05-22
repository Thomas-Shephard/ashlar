namespace Ashlar.Operational.Diagnostics;

internal static class DiagnosticsQueryRunner
{
    public static async Task<TResult> CheckAsync<TConnection, TSnapshot, TResult>(
        TimeProvider timeProvider,
        DiagnosticsQueryContext<TConnection, TSnapshot> context,
        Func<AshlarDiagnosticStatus, string?, DateTimeOffset, TSnapshot?, TResult> createResult,
        CancellationToken cancellationToken)
        where TConnection : IAsyncDisposable
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(createResult);

        var checkedAt = timeProvider.GetUtcNow();
        TResult result;

        try
        {
            await using var connection = await context.OpenConnectionAsync(cancellationToken);
            if (!await context.TableExistsAsync(connection, cancellationToken))
            {
                result = createResult(AshlarDiagnosticStatus.NotSupported, context.MissingTableReason, checkedAt, default);
            }
            else
            {
                var snapshot = await context.QuerySnapshotAsync(connection, checkedAt, cancellationToken);
                result = createResult(AshlarDiagnosticStatus.Healthy, null, checkedAt, snapshot);
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            context.LogException(ex);
            return createResult(AshlarDiagnosticStatus.Unknown, context.UnknownReason, checkedAt, default);
        }

        return result;
    }
}
