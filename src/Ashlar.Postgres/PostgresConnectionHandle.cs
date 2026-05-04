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

    internal PostgresConnectionHandle(NpgsqlConnection connection, bool shouldDispose)
    {
        Connection = connection;
        _shouldDispose = shouldDispose;
    }

    /// <summary>
    /// Gets the connection.
    /// </summary>
    public NpgsqlConnection Connection { get; }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (_shouldDispose)
        {
            await Connection.DisposeAsync();
        }
    }
}
