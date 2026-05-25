using Microsoft.Extensions.DependencyInjection;

namespace Ashlar.Sqlite.Messaging;

internal sealed record SqliteOutboxFailureUpdate(
    int AttemptCount,
    DateTimeOffset? FailedAt,
    DateTimeOffset AvailableAt,
    string LastError);

internal static class SqliteOutboxDispatch
{
    private const string LockedByParameter = "$lockedBy";
    private const string NowParameter = "$now";

    public static async Task<int> ProcessBatchAsync<TEntry>(
        IServiceProvider serviceProvider,
        string tableName,
        string lockId,
        TimeProvider timeProvider,
        TimeSpan lockDuration,
        int batchSize,
        Func<IServiceProvider, string, CancellationToken, Task<List<TEntry>>> loadClaimedEntriesAsync,
        Func<TEntry, IServiceProvider, CancellationToken, Task> processEntryAsync,
        CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();
        var lockedUntil = now.Add(lockDuration);

        await using var scope = serviceProvider.CreateAsyncScope();
        var connectionProvider = scope.ServiceProvider.GetRequiredService<ISqliteConnectionProvider>();
        await using (var connectionHandle = await connectionProvider.GetConnectionAsync(cancellationToken))
        {
            await using var command = connectionHandle.Connection.CreateCommand();
            command.Transaction = connectionHandle.Transaction;
            command.CommandText = $"""
                UPDATE {tableName}
                SET locked_until = $lockedUntil,
                    locked_by = $lockedBy
                WHERE id IN (
                    SELECT id
                    FROM {tableName}
                    WHERE sent_at IS NULL
                      AND failed_at IS NULL
                      AND available_at <= $now
                      AND (locked_until IS NULL OR locked_until < $now)
                    ORDER BY available_at, id
                    LIMIT $batchSize
                )
                """;
            command.AddDateTimeOffsetParameter("$lockedUntil", lockedUntil);
            command.AddParameter(LockedByParameter, lockId);
            command.AddDateTimeOffsetParameter(NowParameter, now);
            command.AddParameter("$batchSize", batchSize);

            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        var entries = await loadClaimedEntriesAsync(scope.ServiceProvider, lockId, cancellationToken);
        if (entries.Count == 0)
        {
            return 0;
        }

        foreach (var entry in entries)
        {
            await using var entryScope = serviceProvider.CreateAsyncScope();
            await processEntryAsync(entry, entryScope.ServiceProvider, cancellationToken);
        }

        return entries.Count;
    }

    public static async Task MarkAsSentAsync(
        IServiceProvider provider,
        string tableName,
        Guid id,
        string lockId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var connectionProvider = provider.GetRequiredService<ISqliteConnectionProvider>();
        await using var connectionHandle = await connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = connectionHandle.Connection.CreateCommand();
        command.Transaction = connectionHandle.Transaction;
        command.CommandText = $"""
            UPDATE {tableName}
            SET sent_at = $now,
                locked_until = NULL,
                locked_by = NULL,
                last_attempt_at = $now,
                attempt_count = attempt_count + 1
            WHERE id = $id AND locked_by = $lockedBy
            """;
        command.AddDateTimeOffsetParameter(NowParameter, now);
        command.AddGuidParameter("$id", id);
        command.AddParameter(LockedByParameter, lockId);

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public static async Task MarkAsFailedAsync(
        IServiceProvider provider,
        string tableName,
        Guid id,
        string lockId,
        DateTimeOffset now,
        SqliteOutboxFailureUpdate failure,
        CancellationToken cancellationToken)
    {
        var connectionProvider = provider.GetRequiredService<ISqliteConnectionProvider>();
        await using var connectionHandle = await connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = connectionHandle.Connection.CreateCommand();
        command.Transaction = connectionHandle.Transaction;
        command.CommandText = $"""
            UPDATE {tableName}
            SET failed_at = $failedAt,
                last_error = $lastError,
                available_at = $availableAt,
                locked_until = NULL,
                locked_by = NULL,
                last_attempt_at = $now,
                attempt_count = $attemptCount
            WHERE id = $id AND locked_by = $lockedBy
            """;
        command.AddNullableDateTimeOffsetParameter("$failedAt", failure.FailedAt);
        command.AddParameter("$lastError", failure.LastError);
        command.AddDateTimeOffsetParameter("$availableAt", failure.AvailableAt);
        command.AddDateTimeOffsetParameter(NowParameter, now);
        command.AddParameter("$attemptCount", failure.AttemptCount);
        command.AddGuidParameter("$id", id);
        command.AddParameter(LockedByParameter, lockId);

        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
