using Microsoft.Data.Sqlite;

namespace Ashlar.Sqlite.Connections;

internal sealed class SqliteConnectionHandle : IAsyncDisposable
{
    private readonly bool _shouldDispose;
    private bool _disposed;

    internal SqliteConnectionHandle(SqliteConnection connection, SqliteTransaction? transaction, bool shouldDispose)
    {
        Connection = connection;
        Transaction = transaction;
        _shouldDispose = shouldDispose;
    }

    public SqliteConnection Connection { get; }

    public SqliteTransaction? Transaction { get; }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        if (_shouldDispose)
        {
            await Connection.DisposeAsync();
        }
    }
}
