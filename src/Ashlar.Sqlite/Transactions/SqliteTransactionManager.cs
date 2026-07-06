using System.Data;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;

namespace Ashlar.Sqlite.Transactions;

/// <summary>
/// Manages the SQLite connection and transaction lifecycle for a scoped database interaction.
/// </summary>
internal sealed partial class SqliteTransactionManager : IAshlarDurableTransactionProvider, ISqliteConnectionProvider, IAsyncDisposable
{
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
        _logger = logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger<SqliteTransactionManager>.Instance;
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
                return new TransactionParticipant(this, transaction: null);
            }

            _connection ??= await _openConnectionAsync(cancellationToken);
            _transaction = await BeginImmediateTransactionAsync(_connection, cancellationToken);
            _mustRollback = false;
            return new TransactionParticipant(this, _transaction);
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

    // Microsoft.Data.Sqlite does not expose an async BeginTransaction overload with deferred: false.
    // Use the synchronous overload here so root transactions issue BEGIN IMMEDIATE for write safety.
    private static Task<SqliteTransaction> BeginImmediateTransactionAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(connection.BeginTransaction(IsolationLevel.Serializable, deferred: false));
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

    private async Task CompleteRootAsync(SqliteTransaction transaction, CancellationToken cancellationToken)
    {
        if (_mustRollback)
        {
            throw new InvalidOperationException("The transaction cannot be committed because it has been marked for rollback by a nested participant.");
        }

        await transaction.CommitAsync(cancellationToken);
        var hooks = _postCommitHooks.ToArray();
        await ClearTransactionAsync();
        await RunPostCommitHooksAsync(hooks);
    }

    private async Task RunPostCommitHooksAsync(Func<CancellationToken, Task>[] hooks)
    {
        for (var i = 0; i < hooks.Length; i++)
        {
            try
            {
                await hooks[i](CancellationToken.None);
            }
            catch (Exception ex)
            {
                LogPostCommitHookFailed(_logger, i, hooks.Length, ex);
            }
        }
    }

    [LoggerMessage(EventId = 1000, Level = LogLevel.Warning, Message = "Post-commit hook failed. HookIndex={HookIndex} HookCount={HookCount}")]
    private static partial void LogPostCommitHookFailed(ILogger logger, int hookIndex, int hookCount, Exception exception);

    private sealed class TransactionParticipant(SqliteTransactionManager manager, SqliteTransaction? transaction) : IAshlarTransaction
    {
        private bool _committed;
        private bool _disposed;
        private bool IsRoot => transaction != null;

        public async Task CommitAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ObjectDisposedException.ThrowIf(_disposed, this);

            if (IsRoot)
            {
                await manager.CompleteRootAsync(transaction!, cancellationToken);
                _disposed = true;
                return;
            }

            _committed = true;
        }

        public async Task RollbackAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ObjectDisposedException.ThrowIf(_disposed, this);

            if (IsRoot)
            {
                await transaction!.RollbackAsync(cancellationToken);
                await manager.ClearTransactionAsync();
            }
            else
            {
                manager._mustRollback = true;
            }

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

            if (IsRoot)
            {
                await manager.ClearTransactionAsync();
                return;
            }

            if (!_committed)
            {
                manager._mustRollback = true;
            }
        }
    }
}
