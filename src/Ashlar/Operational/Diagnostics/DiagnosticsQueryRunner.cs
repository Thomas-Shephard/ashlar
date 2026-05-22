namespace Ashlar.Operational.Diagnostics;

internal static class DiagnosticsQueryRunner
{
    public static async Task<TResult> CheckAsync<TConnection, TSnapshot, TResult>(
        TimeProvider timeProvider,
        DiagnosticsQueryContext<TConnection, TSnapshot, TResult> context,
        CancellationToken cancellationToken)
        where TConnection : IAsyncDisposable
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(context);

        var checkedAt = timeProvider.GetUtcNow();
        TResult result;

        try
        {
            await using var connection = await context.OpenConnectionAsync(cancellationToken);
            if (!await context.TableExistsAsync(connection, cancellationToken))
            {
                result = context.CreateResult(AshlarDiagnosticStatus.NotSupported, context.MissingTableReason, checkedAt, default);
            }
            else
            {
                var snapshot = await context.QuerySnapshotAsync(connection, checkedAt, cancellationToken);
                result = context.CreateResult(AshlarDiagnosticStatus.Healthy, null, checkedAt, snapshot);
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            context.LogException(ex);
            return context.CreateResult(AshlarDiagnosticStatus.Unknown, context.UnknownReason, checkedAt, default);
        }

        return result;
    }
}
