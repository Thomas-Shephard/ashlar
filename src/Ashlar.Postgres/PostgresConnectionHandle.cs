using Npgsql;

namespace Ashlar.Postgres;

/// <summary>
/// A handle to an <see cref="NpgsqlConnection"/> that can be disposed safely.
/// </summary>
/// <remarks>
/// If the connection is part of an active transaction, disposing the handle does nothing.
/// If the connection was opened specifically for a query outside of a transaction, disposing the handle closes the connection.
/// </remarks>
public sealed class PostgresConnectionHandle : IAsyncDisposable
{
    private readonly bool _shouldDispose;
    private bool _disposed;

    internal PostgresConnectionHandle(NpgsqlConnection connection, NpgsqlTransaction? transaction, bool shouldDispose)
    {
        Connection = connection;
        Transaction = transaction;
        _shouldDispose = shouldDispose;
    }

    /// <summary>
    /// Gets the connection.
    /// </summary>
    public NpgsqlConnection Connection { get; }

    /// <summary>
    /// Gets the active transaction, if any.
    /// </summary>
    public NpgsqlTransaction? Transaction { get; }

    /// <summary>
    /// Disposes the owned PostgreSQL connection when this handle owns it.
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
