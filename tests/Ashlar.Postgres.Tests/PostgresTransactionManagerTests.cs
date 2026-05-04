using Npgsql;
using System.Data;

namespace Ashlar.Postgres.Tests;

public sealed class PostgresTransactionManagerTests : PostgresTestBase
{
    [Test]
    public void ConstructorRejectsNullDataSource()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new PostgresTransactionManager(null!));
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
    public void BeginTransactionAsyncThrowsWhenTransactionAlreadyInProgress()
    {
        Assert.ThrowsAsync<InvalidOperationException>(BeginNestedTransactionAsync);
    }

    private static async Task<int> ExecuteScalarAsync(NpgsqlConnection connection)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT 1";

        var result = await command.ExecuteScalarAsync();
        Assert.That(result, Is.Not.Null);

        return (int)result;
    }

    private async Task BeginNestedTransactionAsync()
    {
        await using var manager = new PostgresTransactionManager(GetDataSource());
        await using var transaction = await manager.BeginTransactionAsync();

        await manager.BeginTransactionAsync();
    }
}
