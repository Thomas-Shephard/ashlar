using Microsoft.Data.Sqlite;

namespace Ashlar.Sqlite.Connections;

internal static class SqliteQuery
{
    public static async Task<IReadOnlyList<T>> QueryAsync<T>(
        ISqliteConnectionProvider connectionProvider,
        Func<SqliteCommand, string> buildSql,
        Func<SqliteDataReader, T> read,
        CancellationToken cancellationToken)
    {
        await using var handle = await connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = buildSql(command);

        var items = new List<T>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            items.Add(read(reader));
        }

        return items.AsReadOnly();
    }

    public static async Task<T?> QuerySingleAsync<T>(
        ISqliteConnectionProvider connectionProvider,
        Func<SqliteCommand, string> buildSql,
        Func<SqliteDataReader, T> read,
        CancellationToken cancellationToken)
    {
        await using var handle = await connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = buildSql(command);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? read(reader) : default;
    }
}
