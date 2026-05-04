using Npgsql;
using System.Data;

namespace Ashlar.Postgres.Tests;

public sealed class PostgresTransactionManagerTests : PostgresTestBase
{
    [Test]
    public void ConstructorRejectsNullDataSource()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new PostgresTransactionManager((NpgsqlDataSource)null!));
    }

    [Test]
    public void ConstructorRejectsNullConnectionFactory()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new PostgresTransactionManager((Func<CancellationToken, ValueTask<NpgsqlConnection>>)null!));
    }

    [Test]
    public async Task GetConnectionAsyncDuringTransactionReturnsTransactionalConnection()
    {
        await using var manager = new PostgresTransactionManager(GetDataSource());
        await using var transaction = await manager.BeginTransactionAsync();

        await using var connectionHandle = await manager.GetConnectionAsync(CancellationToken.None);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(connectionHandle.Transaction, Is.Not.Null);
            Assert.That(await ExecuteScalarAsync(connectionHandle.Connection), Is.EqualTo(1));
        }
    }

    [Test]
    public async Task GetConnectionAsyncAfterCommitReturnsConnectionWithoutCompletedTransaction()
    {
        await using var manager = new PostgresTransactionManager(GetDataSource());
        await using var transaction = await manager.BeginTransactionAsync();

        await transaction.CommitAsync();

        await using var connectionHandle = await manager.GetConnectionAsync(CancellationToken.None);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(connectionHandle.Transaction, Is.Null);
            Assert.That(await ExecuteScalarAsync(connectionHandle.Connection), Is.EqualTo(1));
        }
    }

    [Test]
    public async Task GetConnectionAsyncAfterRollbackReturnsConnectionWithoutCompletedTransaction()
    {
        await using var manager = new PostgresTransactionManager(GetDataSource());
        await using var transaction = await manager.BeginTransactionAsync();

        await transaction.RollbackAsync();

        await using var connectionHandle = await manager.GetConnectionAsync(CancellationToken.None);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(connectionHandle.Transaction, Is.Null);
            Assert.That(await ExecuteScalarAsync(connectionHandle.Connection), Is.EqualTo(1));
        }
    }

    [Test]
    public async Task GetConnectionAsyncHandleCanBeDisposedMoreThanOnce()
    {
        await using var manager = new PostgresTransactionManager(GetDataSource());
        var connectionHandle = await manager.GetConnectionAsync(CancellationToken.None);

        await connectionHandle.DisposeAsync();
        await connectionHandle.DisposeAsync();

        Assert.That(connectionHandle.Connection.FullState, Is.Not.EqualTo(ConnectionState.Open));
    }

    [Test]
    public async Task BeginTransactionAsyncJoinsWhenTransactionAlreadyInProgress()
    {
        await using var manager = new PostgresTransactionManager(GetDataSource());
        await using var outer = await manager.BeginTransactionAsync();
        await using var inner = await manager.BeginTransactionAsync();

        Assert.That(inner, Is.Not.Null);
    }

    [Test]
    public async Task NestedCommitAllowsOuterCommit()
    {
        await using var manager = new PostgresTransactionManager(GetDataSource());
        await using var outer = await manager.BeginTransactionAsync();

        await using (var inner = await manager.BeginTransactionAsync())
        {
            await inner.CommitAsync();
        }

        await outer.CommitAsync();

        await using var connectionHandle = await manager.GetConnectionAsync(CancellationToken.None);
        Assert.That(connectionHandle.Transaction, Is.Null);
    }

    [Test]
    public async Task NestedTransactionCommitRejectsDisposedTransaction()
    {
        await using var manager = new PostgresTransactionManager(GetDataSource());
        await using var outer = await manager.BeginTransactionAsync();
        var inner = await manager.BeginTransactionAsync();

        await inner.DisposeAsync();

        await AssertCommitThrowsObjectDisposedAsync(inner);
        await AssertCommitThrowsInvalidOperationAsync(outer);
    }

    [Test]
    public async Task NestedRollbackPreventsOuterCommit()
    {
        await using var manager = new PostgresTransactionManager(GetDataSource());
        await using var outer = await manager.BeginTransactionAsync();

        await using (var inner = await manager.BeginTransactionAsync())
        {
            await inner.RollbackAsync();
        }

        await AssertCommitThrowsInvalidOperationAsync(outer);
    }

    [Test]
    public async Task NestedDisposalWithoutCommitPreventsOuterCommit()
    {
        await using var manager = new PostgresTransactionManager(GetDataSource());
        await using var outer = await manager.BeginTransactionAsync();

        await using (var _ = await manager.BeginTransactionAsync())
        {
            // Dispose without calling CommitAsync or RollbackAsync
        }

        await AssertCommitThrowsInvalidOperationAsync(outer);
    }

    [Test]
    public async Task NestedDisposalCanBeCalledMoreThanOnce()
    {
        await using var manager = new PostgresTransactionManager(GetDataSource());
        await using var outer = await manager.BeginTransactionAsync();
        var inner = await manager.BeginTransactionAsync();

        await inner.DisposeAsync();
        await inner.DisposeAsync();

        await AssertCommitThrowsInvalidOperationAsync(outer);
    }

    [Test]
    public async Task BeginTransactionAsyncDisposesCachedConnectionWhenBeginFails()
    {
        var connection = new NpgsqlConnection();
        await using var manager = new PostgresTransactionManager(_ => ValueTask.FromResult(connection));

        await AssertBeginTransactionThrowsInvalidOperationAsync(manager);
        Assert.That(connection.FullState, Is.Not.EqualTo(ConnectionState.Open));
    }

    private static async Task AssertCommitThrowsObjectDisposedAsync(Ashlar.Identity.Abstractions.IAshlarTransaction transaction)
    {
        try
        {
            await transaction.CommitAsync();
        }
        catch (ObjectDisposedException)
        {
            return;
        }

        Assert.Fail("Expected ObjectDisposedException.");
    }

    private static async Task AssertCommitThrowsInvalidOperationAsync(Ashlar.Identity.Abstractions.IAshlarTransaction transaction)
    {
        try
        {
            await transaction.CommitAsync();
        }
        catch (InvalidOperationException)
        {
            return;
        }

        Assert.Fail("Expected InvalidOperationException.");
    }

    private static async Task AssertBeginTransactionThrowsInvalidOperationAsync(PostgresTransactionManager manager)
    {
        try
        {
            await manager.BeginTransactionAsync();
        }
        catch (InvalidOperationException)
        {
            return;
        }

        Assert.Fail("Expected InvalidOperationException.");
    }

    private static async Task<int> ExecuteScalarAsync(NpgsqlConnection connection)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT 1";

        var result = await command.ExecuteScalarAsync();
        Assert.That(result, Is.Not.Null);

        return (int)result;
    }
}
