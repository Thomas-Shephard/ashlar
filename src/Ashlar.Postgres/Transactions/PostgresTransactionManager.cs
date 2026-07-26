using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;

namespace Ashlar.Postgres.Transactions;

internal sealed class PostgresTransactionManager : IAshlarTransactionProvider, IPostgresConnectionProvider, IAsyncDisposable
{
    private static readonly Action<ILogger, int, int, Exception?> PostCommitHookFailed =
        LoggerMessage.Define<int, int>(
            LogLevel.Warning,
            new EventId(1000, nameof(PostCommitHookFailed)),
            "Post-commit hook failed. HookIndex={HookIndex} HookCount={HookCount}");

    private readonly Func<CancellationToken, ValueTask<NpgsqlConnection>> _openConnectionAsync;
    private readonly ILogger<PostgresTransactionManager> _logger;
    private readonly SemaphoreSlim _connectionLock = new(1, 1);
    private readonly List<Func<CancellationToken, Task>> _postCommitHooks = [];
    private readonly AsyncLocal<object?> _ambientRoot = new();
    private NpgsqlConnection? _connection;
    private NpgsqlTransaction? _transaction;
    private object? _activeRoot;
    private volatile bool _mustRollback;

    /// <summary>
    /// Initializes a new instance of the postgres transaction manager class.
    /// </summary>
    /// <param name="dataSource">The data source value.</param>
    /// <param name="logger">The logger value.</param>
    public PostgresTransactionManager(NpgsqlDataSource dataSource, ILogger<PostgresTransactionManager>? logger = null)
        : this((dataSource ?? throw new ArgumentNullException(nameof(dataSource))).OpenConnectionAsync, logger)
    {
    }

    internal PostgresTransactionManager(
        Func<CancellationToken, ValueTask<NpgsqlConnection>> openConnectionAsync,
        ILogger<PostgresTransactionManager>? logger = null)
    {
        _openConnectionAsync = openConnectionAsync ?? throw new ArgumentNullException(nameof(openConnectionAsync));
        _logger = logger ?? NullLogger<PostgresTransactionManager>.Instance;
    }

    private void RegisterPostCommitHook(Func<CancellationToken, Task> action)
    {
        _postCommitHooks.Add(action ?? throw new ArgumentNullException(nameof(action)));
    }

    public async ValueTask<PostgresConnectionHandle> GetConnectionAsync(CancellationToken cancellationToken)
    {
        await _connectionLock.WaitAsync(cancellationToken);
        try
        {
            // If there is an active transaction, use its connection.
            if (_connection != null)
            {
                if (_transaction != null && !ReferenceEquals(_activeRoot, _ambientRoot.Value))
                {
                    throw new InvalidOperationException("The active transaction belongs to a different async flow.");
                }

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

    public Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default)
    {
        var root = _ambientRoot.Value;
        if (root is null || !ReferenceEquals(root, Volatile.Read(ref _activeRoot)))
        {
            _ambientRoot.Value = root = new object();
        }

        return BeginTransactionCoreAsync(root, cancellationToken);
    }

    private async Task<IAshlarTransaction> BeginTransactionCoreAsync(object root, CancellationToken cancellationToken)
    {
        await _connectionLock.WaitAsync(cancellationToken);
        try
        {
            if (_transaction != null)
            {
                if (!ReferenceEquals(_activeRoot, root))
                {
                    throw new InvalidOperationException("A concurrent independent transaction root is already active in this transaction manager.");
                }

                // Join the existing transaction.
                return new JointTransaction(this);
            }

            _activeRoot = root;
            _connection ??= await _openConnectionAsync(cancellationToken);
            _transaction = await _connection.BeginTransactionAsync(cancellationToken);
            _mustRollback = false;
            return new PostgresTransaction(_transaction, this);
        }
        catch
        {
            if (ReferenceEquals(_activeRoot, root))
            {
                var conn = _connection;
                _connection = null;
                _activeRoot = null;
                if (conn != null)
                {
                    await conn.DisposeAsync();
                }
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
            _disposed = true;
            return Task.CompletedTask;
        }

        public void OnCommitted(Func<CancellationToken, Task> action)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            manager.RegisterPostCommitHook(action);
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
            _activeRoot = null;
            _mustRollback = false;
            _postCommitHooks.Clear();
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

            // Capture hooks before clearing the transaction state.
            var hooks = manager._postCommitHooks.ToArray();

            await manager.ClearTransactionAsync();
            _disposed = true;

            for (var i = 0; i < hooks.Length; i++)
            {
                try
                {
                    await hooks[i](CancellationToken.None);
                }
                catch (Exception ex)
                {
                    PostCommitHookFailed(manager._logger, i, hooks.Length, ex);
                }
            }
        }

        public async Task RollbackAsync(CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            await transaction.RollbackAsync(cancellationToken);
            await manager.ClearTransactionAsync();
            _disposed = true;
        }

        public void OnCommitted(Func<CancellationToken, Task> action)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            manager.RegisterPostCommitHook(action);
        }

        public async ValueTask DisposeAsync()
        {
            if (_disposed) return;
            _disposed = true;
            await manager.ClearTransactionAsync();
        }
    }
}
