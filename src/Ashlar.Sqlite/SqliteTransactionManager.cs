using Ashlar.Identity.Abstractions;
using System.Data;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Ashlar.Sqlite;

/// <summary>
/// Manages the SQLite connection and transaction lifecycle for a scoped database interaction.
/// </summary>
internal sealed class SqliteTransactionManager : IAshlarTransactionProvider, ISqliteConnectionProvider, IAsyncDisposable
{
    private static readonly Action<ILogger, int, int, Exception?> PostCommitHookFailed =
        LoggerMessage.Define<int, int>(
            LogLevel.Warning,
            new EventId(1000, nameof(PostCommitHookFailed)),
            "Post-commit hook failed. HookIndex={HookIndex} HookCount={HookCount}");

    private readonly Func<CancellationToken, ValueTask<SqliteConnection>> _openConnectionAsync;
    private readonly ILogger<SqliteTransactionManager> _logger;
    private readonly SemaphoreSlim _connectionLock = new(1, 1);
    private readonly List<Func<CancellationToken, Task>> _postCommitHooks = [];
    private SqliteConnection? _connection;
    private SqliteTransaction? _transaction;
    private volatile bool _mustRollback;
    private bool _disposed;

    public SqliteTransactionManager(SqliteConnectionFactory connectionFactory, ILogger<SqliteTransactionManager>? logger = null)
        : this((connectionFactory ?? throw new ArgumentNullException(nameof(connectionFactory))).OpenConnectionAsync, logger)
    {
    }

    internal SqliteTransactionManager(
        Func<CancellationToken, ValueTask<SqliteConnection>> openConnectionAsync,
        ILogger<SqliteTransactionManager>? logger = null)
    {
        _openConnectionAsync = openConnectionAsync ?? throw new ArgumentNullException(nameof(openConnectionAsync));
        _logger = logger ?? NullLogger<SqliteTransactionManager>.Instance;
    }

    public async ValueTask<SqliteConnectionHandle> GetConnectionAsync(CancellationToken cancellationToken)
    {
        await _connectionLock.WaitAsync(cancellationToken);
        try
        {
            if (_connection != null)
            {
                return new SqliteConnectionHandle(_connection, _transaction, shouldDispose: false);
            }

            var connection = await _openConnectionAsync(cancellationToken);
            return new SqliteConnectionHandle(connection, transaction: null, shouldDispose: true);
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
                return new JointTransaction(this);
            }

            _connection ??= await _openConnectionAsync(cancellationToken);
            _transaction = await BeginImmediateTransactionAsync(_connection, cancellationToken);
            _mustRollback = false;
            return new SqliteAshlarTransaction(_transaction, this);
        }
        catch
        {
            if (_connection != null)
            {
                var connection = _connection;
                _connection = null;
                await connection.DisposeAsync();
            }

            throw;
        }
        finally
        {
            _connectionLock.Release();
        }
    }

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

    private static async Task<SqliteTransaction> BeginImmediateTransactionAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        return (SqliteTransaction)await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
    }

    private void RegisterPostCommitHook(Func<CancellationToken, Task> action)
    {
        _postCommitHooks.Add(action ?? throw new ArgumentNullException(nameof(action)));
    }

    private async ValueTask ClearTransactionAsync()
    {
        SqliteTransaction? transaction;
        SqliteConnection? connection;

        await _connectionLock.WaitAsync();
        try
        {
            transaction = _transaction;
            connection = _connection;

            _transaction = null;
            _connection = null;
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

    private sealed class JointTransaction(SqliteTransactionManager manager) : IAshlarTransaction
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

        public void OnCommitted(Func<CancellationToken, Task> action)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            manager.RegisterPostCommitHook(action);
        }

        public ValueTask DisposeAsync()
        {
            if (_disposed)
            {
                return ValueTask.CompletedTask;
            }

            _disposed = true;

            if (!_committed)
            {
                manager._mustRollback = true;
            }

            return ValueTask.CompletedTask;
        }
    }

    private sealed class SqliteAshlarTransaction(SqliteTransaction transaction, SqliteTransactionManager manager) : IAshlarTransaction
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
            var hooks = manager._postCommitHooks.ToArray();

            await manager.ClearTransactionAsync();
            _disposed = true;

            List<Exception>? hookExceptions = null;
            for (var i = 0; i < hooks.Length; i++)
            {
                try
                {
                    await hooks[i](CancellationToken.None);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    PostCommitHookFailed(manager._logger, i, hooks.Length, ex);
                    (hookExceptions ??= []).Add(ex);
                }
            }

            if (hookExceptions != null)
            {
                throw new AggregateException("One or more post-commit hooks failed.", hookExceptions);
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
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            await manager.ClearTransactionAsync();
        }
    }
}
