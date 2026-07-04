using Npgsql;

namespace Ashlar.Postgres.Connections;

internal sealed class PostgresConnectionHandle : IAsyncDisposable
{
    private readonly bool _shouldDispose;
    private bool _disposed;

    internal PostgresConnectionHandle(NpgsqlConnection connection, NpgsqlTransaction? transaction, bool shouldDispose)
    {
        Connection = connection;
        Transaction = transaction;
        _shouldDispose = shouldDispose;
    }

    public NpgsqlConnection Connection { get; }

    public NpgsqlTransaction? Transaction { get; }

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
