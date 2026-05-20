using Microsoft.Data.Sqlite;

namespace Ashlar.Sqlite.Connections;

/// <summary>
/// A handle to a <see cref="SqliteConnection"/> that can be disposed safely.
/// </summary>
public sealed class SqliteConnectionHandle : IAsyncDisposable
{
    private readonly bool _shouldDispose;
    private bool _disposed;

    internal SqliteConnectionHandle(SqliteConnection connection, SqliteTransaction? transaction, bool shouldDispose)
    {
        Connection = connection;
        Transaction = transaction;
        _shouldDispose = shouldDispose;
    }

    /// <summary>
    /// Gets the connection.
    /// </summary>
    public SqliteConnection Connection { get; }

    /// <summary>
    /// Gets the active transaction, if any.
    /// </summary>
    public SqliteTransaction? Transaction { get; }

    /// <summary>
    /// Disposes the owned SQLite connection when this handle owns it.
    /// </summary>
    /// <returns>A value task that represents the asynchronous dispose operation.</returns>
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
