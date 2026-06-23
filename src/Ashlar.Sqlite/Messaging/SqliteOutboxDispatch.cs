using Microsoft.Extensions.DependencyInjection;

namespace Ashlar.Sqlite.Messaging;

internal sealed record SqliteOutboxFailureUpdate(
    int AttemptCount,
    DateTimeOffset? FailedAt,
    DateTimeOffset AvailableAt,
    string LastError);

internal sealed record SqliteOutboxProcessContext<TEntry>(
    IServiceProvider ServiceProvider,
    string ClaimSql,
    string LockId,
    TimeProvider TimeProvider,
    TimeSpan LockDuration,
    int BatchSize,
    Func<IServiceProvider, string, CancellationToken, Task<List<TEntry>>> LoadClaimedEntriesAsync,
    Func<TEntry, IServiceProvider, CancellationToken, Task> ProcessEntryAsync);

internal sealed record SqliteOutboxSentUpdateContext(
    IServiceProvider ServiceProvider,
    string Sql,
    string LockId,
    DateTimeOffset Now);

internal sealed record SqliteOutboxFailedUpdateContext(
    IServiceProvider ServiceProvider,
    string Sql,
    string LockId,
    DateTimeOffset Now);

internal static class SqliteOutboxDispatch
{
    private const string LockedByParameter = "$lockedBy";
    private const string NowParameter = "$now";

    public static async Task<int> ProcessBatchAsync<TEntry>(
        SqliteOutboxProcessContext<TEntry> context,
        CancellationToken cancellationToken)
    {
        var now = context.TimeProvider.GetUtcNow();
        var lockedUntil = now.Add(context.LockDuration);

        await using var scope = context.ServiceProvider.CreateAsyncScope();
        var connectionProvider = scope.ServiceProvider.GetRequiredService<ISqliteConnectionProvider>();
        await using (var connectionHandle = await connectionProvider.GetConnectionAsync(cancellationToken))
        {
            await using var command = connectionHandle.Connection.CreateCommand();
            command.Transaction = connectionHandle.Transaction;
            command.CommandText = context.ClaimSql;
            command.AddDateTimeOffsetParameter("$lockedUntil", lockedUntil);
            command.AddParameter(LockedByParameter, context.LockId);
            command.AddDateTimeOffsetParameter(NowParameter, now);
            command.AddParameter("$batchSize", context.BatchSize);

            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        var entries = await context.LoadClaimedEntriesAsync(scope.ServiceProvider, context.LockId, cancellationToken);
        if (entries.Count == 0)
        {
            return 0;
        }

        foreach (var entry in entries)
        {
            await using var entryScope = context.ServiceProvider.CreateAsyncScope();
            await context.ProcessEntryAsync(entry, entryScope.ServiceProvider, cancellationToken);
        }

        return entries.Count;
    }

    public static async Task<bool> MarkAsSentAsync(
        SqliteOutboxSentUpdateContext context,
        Guid id,
        CancellationToken cancellationToken)
    {
        var connectionProvider = context.ServiceProvider.GetRequiredService<ISqliteConnectionProvider>();
        await using var connectionHandle = await connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = connectionHandle.Connection.CreateCommand();
        command.Transaction = connectionHandle.Transaction;
        command.CommandText = context.Sql;
        command.AddDateTimeOffsetParameter(NowParameter, context.Now);
        command.AddGuidParameter("$id", id);
        command.AddParameter(LockedByParameter, context.LockId);

        return await command.ExecuteNonQueryAsync(cancellationToken) > 0;
    }

    public static async Task MarkAsFailedAsync(
        SqliteOutboxFailedUpdateContext context,
        Guid id,
        SqliteOutboxFailureUpdate failure,
        CancellationToken cancellationToken)
    {
        var connectionProvider = context.ServiceProvider.GetRequiredService<ISqliteConnectionProvider>();
        await using var connectionHandle = await connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = connectionHandle.Connection.CreateCommand();
        command.Transaction = connectionHandle.Transaction;
        command.CommandText = context.Sql;
        command.AddNullableDateTimeOffsetParameter("$failedAt", failure.FailedAt);
        command.AddParameter("$lastError", failure.LastError);
        command.AddDateTimeOffsetParameter("$availableAt", failure.AvailableAt);
        command.AddDateTimeOffsetParameter(NowParameter, context.Now);
        command.AddParameter("$attemptCount", failure.AttemptCount);
        command.AddGuidParameter("$id", id);
        command.AddParameter(LockedByParameter, context.LockId);

        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
