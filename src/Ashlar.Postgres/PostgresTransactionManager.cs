using Ashlar.Identity.Abstractions;
using Npgsql;

namespace Ashlar.Postgres;

/// <summary>
/// Manages the connection and transaction lifecycle for a scoped database interaction.
/// </summary>
internal sealed class PostgresTransactionManager(NpgsqlDataSource dataSource) : IAshlarTransactionProvider, IPostgresConnectionProvider, IAsyncDisposable
{
    private readonly NpgsqlDataSource _dataSource = dataSource ?? throw new ArgumentNullException(nameof(dataSource));
    private readonly SemaphoreSlim _connectionLock = new(1, 1);
    private NpgsqlConnection? _connection;
    private NpgsqlTransaction? _transaction;

    public async ValueTask<PostgresConnectionHandle> GetConnectionAsync(CancellationToken cancellationToken)
    {
        await _connectionLock.WaitAsync(cancellationToken);
        try
        {
            // If there is an active transaction, use its connection.
            if (_connection != null)
            {
                return new PostgresConnectionHandle(_connection, _transaction, shouldDispose: false);
            }

            // Otherwise, use a new connection.
            var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
            return new PostgresConnectionHandle(connection, transaction: null, shouldDispose: true);
        }
        finally
        {
            _connectionLock.Release();
        }
    }

    public async Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default)
    {
        await _connectionLock.WaitAsync(cancellationToken);
        try
        {
            if (_transaction != null)
            {
                throw new InvalidOperationException("A transaction is already in progress.");
            }

            _connection ??= await _dataSource.OpenConnectionAsync(cancellationToken);
            _transaction = await _connection.BeginTransactionAsync(cancellationToken);
            return new PostgresTransaction(_transaction, this);
        }
        catch
        {
            if (_connection != null)
            {
                var conn = _connection;
                _connection = null;
                await conn.DisposeAsync();
            }
            throw;
        }
        finally
        {
            _connectionLock.Release();
        }
    }

    internal async ValueTask ClearTransactionAsync()
    {
        await _connectionLock.WaitAsync();
        try
        {
            _transaction = null;
            if (_connection != null)
            {
                var conn = _connection;
                _connection = null;
                await conn.DisposeAsync();
            }
        }
        finally
        {
            _connectionLock.Release();
        }
    }

    private bool _disposed;

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        try
        {
            if (_transaction != null)
            {
                await _transaction.DisposeAsync();
            }
        }
        finally
        {
            try
            {
                await ClearTransactionAsync();
            }
            finally
            {
                _connectionLock.Dispose();
            }
        }
    }

    private sealed class PostgresTransaction(NpgsqlTransaction transaction, PostgresTransactionManager manager) : IAshlarTransaction
    {
        public Task CommitAsync(CancellationToken cancellationToken = default) => transaction.CommitAsync(cancellationToken);

        public Task RollbackAsync(CancellationToken cancellationToken = default) => transaction.RollbackAsync(cancellationToken);

        public async ValueTask DisposeAsync()
        {
            try
            {
                await transaction.DisposeAsync();
            }
            finally
            {
                await manager.ClearTransactionAsync();
            }
        }
    }
}
