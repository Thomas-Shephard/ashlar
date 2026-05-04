using Ashlar.Identity.Abstractions;
using Npgsql;

namespace Ashlar.Postgres;

/// <summary>
/// Manages the connection and transaction lifecycle for a scoped database interaction.
/// </summary>
internal sealed class PostgresTransactionManager : IAshlarTransactionProvider, IPostgresConnectionProvider, IAsyncDisposable
{
    private readonly Func<CancellationToken, ValueTask<NpgsqlConnection>> _openConnectionAsync;
    private readonly SemaphoreSlim _connectionLock = new(1, 1);
    private NpgsqlConnection? _connection;
    private NpgsqlTransaction? _transaction;
    private volatile bool _mustRollback;

    public PostgresTransactionManager(NpgsqlDataSource dataSource)
        : this((dataSource ?? throw new ArgumentNullException(nameof(dataSource))).OpenConnectionAsync)
    {
    }

    internal PostgresTransactionManager(Func<CancellationToken, ValueTask<NpgsqlConnection>> openConnectionAsync)
    {
        _openConnectionAsync = openConnectionAsync ?? throw new ArgumentNullException(nameof(openConnectionAsync));
    }

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
            var connection = await _openConnectionAsync(cancellationToken);
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
                // Join the existing transaction.
                return new JointTransaction(this);
            }

            _connection ??= await _openConnectionAsync(cancellationToken);
            _transaction = await _connection.BeginTransactionAsync(cancellationToken);
            _mustRollback = false;
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

    private sealed class JointTransaction(PostgresTransactionManager manager) : IAshlarTransaction
    {
        private bool _committed;
        private bool _disposed;

        public Task CommitAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ObjectDisposedException.ThrowIf(_disposed, this);
            _committed = true;
            return Task.CompletedTask;
        }

        public Task RollbackAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ObjectDisposedException.ThrowIf(_disposed, this);
            manager._mustRollback = true;
            return Task.CompletedTask;
        }

        public ValueTask DisposeAsync()
        {
            if (_disposed) return ValueTask.CompletedTask;
            _disposed = true;

            if (!_committed)
            {
                manager._mustRollback = true;
            }

            return ValueTask.CompletedTask;
        }
    }

    private async ValueTask ClearTransactionAsync()
    {
        NpgsqlTransaction? transaction;
        NpgsqlConnection? connection;

        await _connectionLock.WaitAsync();
        try
        {
            transaction = _transaction;
            connection = _connection;

            _transaction = null;
            _connection = null;
            _mustRollback = false;
        }
        finally
        {
            _connectionLock.Release();
        }

        if (transaction != null)
        {
            await transaction.DisposeAsync();
        }

        if (connection != null)
        {
            await connection.DisposeAsync();
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
            await ClearTransactionAsync();
        }
        finally
        {
            _connectionLock.Dispose();
        }
    }

    private sealed class PostgresTransaction(NpgsqlTransaction transaction, PostgresTransactionManager manager) : IAshlarTransaction
    {
        private bool _disposed;

        public async Task CommitAsync(CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            if (manager._mustRollback)
            {
                throw new InvalidOperationException("The transaction cannot be committed because it has been marked for rollback by a nested participant.");
            }

            await transaction.CommitAsync(cancellationToken);
            await manager.ClearTransactionAsync();
            _disposed = true;
        }

        public async Task RollbackAsync(CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            await transaction.RollbackAsync(cancellationToken);
            await manager.ClearTransactionAsync();
            _disposed = true;
        }

        public async ValueTask DisposeAsync()
        {
            if (_disposed) return;
            _disposed = true;
            await manager.ClearTransactionAsync();
        }
    }
}
