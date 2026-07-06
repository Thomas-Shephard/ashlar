using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;

namespace Ashlar.Sqlite.Tests.Transactions;

internal sealed class SqliteTransactionManagerTests : SqliteTestBase
{
    [Test]
    public void ConstructorRejectsNullConnectionFactory()
    {
        Assert.Throws<ArgumentNullException>(() => _ = new SqliteTransactionManager((SqliteConnectionFactory)null!));
        Assert.Throws<ArgumentNullException>(() => _ = new SqliteTransactionManager((Func<CancellationToken, ValueTask<SqliteConnection>>)null!));
    }

    [Test]
    public void ConstructorAcceptsNonNullLogger()
    {
        var manager = new SqliteTransactionManager(
            new SqliteConnectionFactory(GetConnectionString()),
            NullLogger<SqliteTransactionManager>.Instance);

        Assert.That(manager, Is.Not.Null);
    }

    [Test]
    public async Task GetConnectionAsyncDuringTransactionReturnsTransactionalConnection()
    {
        await using var manager = CreateManager();
        await using var transaction = await manager.BeginTransactionAsync();

        await using var connectionHandle = await manager.GetConnectionAsync(CancellationToken.None);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(connectionHandle.Transaction, Is.Not.Null);
            Assert.That(await ExecuteScalarAsync(connectionHandle.Connection, connectionHandle.Transaction), Is.EqualTo(1));
        }
    }

    [Test]
    public async Task GetConnectionAsyncOutsideTransactionReturnsOwnedConnection()
    {
        await using var manager = CreateManager();
        var connectionHandle = await manager.GetConnectionAsync(CancellationToken.None);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(connectionHandle.Transaction, Is.Null);
            Assert.That(await ExecuteScalarAsync(connectionHandle.Connection, connectionHandle.Transaction), Is.EqualTo(1));
        }

        await connectionHandle.DisposeAsync();
        await connectionHandle.DisposeAsync();

        Assert.That(connectionHandle.Connection.State, Is.Not.EqualTo(System.Data.ConnectionState.Open));
    }

    [Test]
    public async Task GetConnectionAsyncTransactionalHandleCanBeDisposedMoreThanOnce()
    {
        await using var manager = CreateManager();
        await using var transaction = await manager.BeginTransactionAsync();
        var connectionHandle = await manager.GetConnectionAsync(CancellationToken.None);

        await connectionHandle.DisposeAsync();
        await connectionHandle.DisposeAsync();

        Assert.That(connectionHandle.Connection.State, Is.EqualTo(System.Data.ConnectionState.Open));
    }

    [Test]
    public async Task CommitPersistsChanges()
    {
        await InitializeTableAsync();
        await using var manager = CreateManager();

        await using (var transaction = await manager.BeginTransactionAsync())
        {
            await using var handle = await manager.GetConnectionAsync(CancellationToken.None);
            await InsertValueAsync(handle.Connection, handle.Transaction, "committed");
            await transaction.CommitAsync();
        }

        Assert.That(await CountRowsAsync(), Is.EqualTo(1));
    }

    [Test]
    public async Task RollbackDiscardsChanges()
    {
        await InitializeTableAsync();
        await using var manager = CreateManager();

        await using (var transaction = await manager.BeginTransactionAsync())
        {
            await using var handle = await manager.GetConnectionAsync(CancellationToken.None);
            await InsertValueAsync(handle.Connection, handle.Transaction, "rolled-back");
            await transaction.RollbackAsync();
        }

        Assert.That(await CountRowsAsync(), Is.Zero);
    }

    [Test]
    public async Task DisposeWithoutCommitDiscardsChanges()
    {
        await InitializeTableAsync();
        await using var manager = CreateManager();

        await using (await manager.BeginTransactionAsync())
        {
            await using var handle = await manager.GetConnectionAsync(CancellationToken.None);
            await InsertValueAsync(handle.Connection, handle.Transaction, "disposed");
        }

        Assert.That(await CountRowsAsync(), Is.Zero);
    }

    [Test]
    public async Task NestedCommitAllowsOuterCommit()
    {
        await InitializeTableAsync();
        await using var manager = CreateManager();
        await using var outer = await manager.BeginTransactionAsync();

        await using (var inner = await manager.BeginTransactionAsync())
        {
            await using var handle = await manager.GetConnectionAsync(CancellationToken.None);
            await InsertValueAsync(handle.Connection, handle.Transaction, "nested");
            await inner.CommitAsync();
        }

        await outer.CommitAsync();

        Assert.That(await CountRowsAsync(), Is.EqualTo(1));
    }

    [Test]
    public async Task NestedRollbackPreventsOuterCommit()
    {
        await InitializeTableAsync();
        await using var manager = CreateManager();
        await using var outer = await manager.BeginTransactionAsync();

        await using (var inner = await manager.BeginTransactionAsync())
        {
            await inner.RollbackAsync();
        }

        Assert.ThrowsAsync<InvalidOperationException>(async () => await outer.CommitAsync());
    }

    [Test]
    public async Task NestedDisposalWithoutCommitPreventsOuterCommit()
    {
        await using var manager = CreateManager();
        await using var outer = await manager.BeginTransactionAsync();

        await using (await manager.BeginTransactionAsync())
        {
        }

        Assert.ThrowsAsync<InvalidOperationException>(async () => await outer.CommitAsync());
    }

    [Test]
    public async Task NestedDisposedTransactionRejectsCommitAndCanBeDisposedAgain()
    {
        await using var manager = CreateManager();
        await using var outer = await manager.BeginTransactionAsync();
        var inner = await manager.BeginTransactionAsync();

        await inner.DisposeAsync();
        await inner.DisposeAsync();

        Assert.ThrowsAsync<ObjectDisposedException>(async () => await inner.CommitAsync());
        Assert.ThrowsAsync<InvalidOperationException>(async () => await outer.CommitAsync());
    }

    [Test]
    public async Task BeginTransactionAsyncDisposesCachedConnectionWhenBeginFails()
    {
        var connection = new SqliteConnection();
        await using var manager = new SqliteTransactionManager(_ => ValueTask.FromResult(connection));

        Assert.ThrowsAsync<InvalidOperationException>(async () => await manager.BeginTransactionAsync());

        Assert.That(connection.State, Is.Not.EqualTo(System.Data.ConnectionState.Open));
    }

    [Test]
    public async Task RootTransactionRejectsOperationsAfterCommit()
    {
        await using var manager = CreateManager();
        var transaction = await manager.BeginTransactionAsync();

        await transaction.CommitAsync();

        Assert.ThrowsAsync<ObjectDisposedException>(async () => await transaction.CommitAsync());
        Assert.ThrowsAsync<ObjectDisposedException>(async () => await transaction.RollbackAsync());
        Assert.Throws<ObjectDisposedException>(() => transaction.OnCommitted(_ => Task.CompletedTask));
        await transaction.DisposeAsync();
    }

    [Test]
    public async Task RootTransactionRejectsOperationsAfterRollback()
    {
        await using var manager = CreateManager();
        var transaction = await manager.BeginTransactionAsync();

        await transaction.RollbackAsync();

        Assert.ThrowsAsync<ObjectDisposedException>(async () => await transaction.CommitAsync());
        await transaction.DisposeAsync();
    }

    [Test]
    public async Task OnCommittedRejectsNullAction()
    {
        await using var manager = CreateManager();
        await using var transaction = await manager.BeginTransactionAsync();

        Assert.Throws<ArgumentNullException>(() => transaction.OnCommitted(null!));

        await using var inner = await manager.BeginTransactionAsync();
        Assert.Throws<ArgumentNullException>(() => inner.OnCommitted(null!));
    }

    [Test]
    public async Task PostCommitHooksRunAfterRootCommit()
    {
        await using var manager = CreateManager();
        await using var outer = await manager.BeginTransactionAsync();
        var hookExecuted = false;

        await using (var inner = await manager.BeginTransactionAsync())
        {
            inner.OnCommitted(_ =>
            {
                hookExecuted = true;
                return Task.CompletedTask;
            });

            await inner.CommitAsync();
        }

        Assert.That(hookExecuted, Is.False);

        await outer.CommitAsync();

        Assert.That(hookExecuted, Is.True);
    }

    [Test]
    public async Task PostCommitHookFailuresDoNotThrowAfterCommitAndLaterHooksRun()
    {
        await using var manager = CreateManager();
        await using var transaction = await manager.BeginTransactionAsync();
        var laterHookExecuted = false;

        transaction.OnCommitted(_ => throw new InvalidOperationException("hook failed"));
        transaction.OnCommitted(_ =>
        {
            laterHookExecuted = true;
            return Task.CompletedTask;
        });

        await transaction.CommitAsync();

        Assert.That(laterHookExecuted, Is.True);
    }

    [Test]
    public async Task PostCommitHooksDoNotRunOnRollbackOrDisposal()
    {
        await using (var rollbackManager = CreateManager())
        {
            await using var transaction = await rollbackManager.BeginTransactionAsync();
            var hookExecuted = false;
            transaction.OnCommitted(_ =>
            {
                hookExecuted = true;
                return Task.CompletedTask;
            });

            await transaction.RollbackAsync();
            Assert.That(hookExecuted, Is.False);
        }

        await using (var disposeManager = CreateManager())
        {
            var hookExecuted = false;
            await using (var transaction = await disposeManager.BeginTransactionAsync())
            {
                transaction.OnCommitted(_ =>
                {
                    hookExecuted = true;
                    return Task.CompletedTask;
                });
            }

            Assert.That(hookExecuted, Is.False);
        }
    }

    [Test]
    public async Task DisposeAsyncCanBeCalledMoreThanOnce()
    {
        var manager = CreateManager();

        await manager.DisposeAsync();
        await manager.DisposeAsync();

        Assert.Pass();
    }

    private SqliteTransactionManager CreateManager()
    {
        return new SqliteTransactionManager(new SqliteConnectionFactory(GetConnectionString()));
    }

    private async Task InitializeTableAsync()
    {
        await using var connection = await OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "CREATE TABLE test_values (value TEXT NOT NULL);";
        await command.ExecuteNonQueryAsync();
    }

    private async Task<int> CountRowsAsync()
    {
        await using var connection = await OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM test_values;";
        var result = await command.ExecuteScalarAsync();
        return Convert.ToInt32(result, System.Globalization.CultureInfo.InvariantCulture);
    }

    private static async Task InsertValueAsync(SqliteConnection connection, SqliteTransaction? transaction, string value)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO test_values (value) VALUES ($value);";
        command.Parameters.AddWithValue("$value", value);
        await command.ExecuteNonQueryAsync();
    }

    private static async Task<int> ExecuteScalarAsync(SqliteConnection connection, SqliteTransaction? transaction)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT 1;";
        var result = await command.ExecuteScalarAsync();
        return Convert.ToInt32(result, System.Globalization.CultureInfo.InvariantCulture);
    }
}
