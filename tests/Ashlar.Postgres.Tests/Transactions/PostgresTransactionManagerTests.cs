using Ashlar.Testing;
using Microsoft.Extensions.Logging;
using Npgsql;
using System.Data;

namespace Ashlar.Postgres.Tests.Transactions;

internal sealed class PostgresTransactionManagerTests : PostgresTestBase
{
    private static readonly int[] ExpectedHookExecutionOrder = [1, 2, 3];

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
    public void DisposeAsyncIsIdempotent()
    {
        var manager = new PostgresTransactionManager(_ => throw new AssertionException("Disposal must not open a connection."));

        Assert.DoesNotThrowAsync(async () =>
        {
            await manager.DisposeAsync();
            await manager.DisposeAsync();
        });
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
        IAshlarTransaction inner;

        await using (inner = await manager.BeginTransactionAsync())
        {
            await inner.RollbackAsync();
        }

        await AssertCommitThrowsObjectDisposedAsync(inner);
        await AssertCommitThrowsInvalidOperationAsync(outer);
    }

    [Test]
    public async Task ConcurrentIndependentRootIsRejectedBeforeMutationAndActiveRootCanCommit()
    {
        var tableName = "test_values_" + Guid.NewGuid().ToString("N");
        await InitializeTableAsync(tableName);
        await using var manager = new PostgresTransactionManager(GetDataSource());
        var firstReady = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseFirst = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        var first = Task.Run(async () =>
        {
            await using var transaction = await manager.BeginTransactionAsync();
            await using (var handle = await manager.GetConnectionAsync(CancellationToken.None))
            {
                await InsertValueAsync(handle.Connection, handle.Transaction, tableName, "first");
            }

            firstReady.SetResult();
            await releaseFirst.Task;
            await transaction.CommitAsync();
        });

        await firstReady.Task;
        var secondMutated = false;
        Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            await Task.Run(async () =>
            {
                await using var transaction = await manager.BeginTransactionAsync();
                secondMutated = true;
            });
        });
        Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await Task.Run(async () => await manager.GetConnectionAsync(CancellationToken.None)));

        releaseFirst.SetResult();
        await first;

        using (Assert.EnterMultipleScope())
        {
            Assert.That(secondMutated, Is.False);
            Assert.That(await CountRowsAsync(tableName), Is.EqualTo(1));
        }
    }

    [Test]
    public async Task ConcurrentInheritedNestedTransactionIsRejected()
    {
        await using var manager = new PostgresTransactionManager(GetDataSource());
        var provider = DurableTransactionComposition.Create(manager);
        await using var root = await provider.BeginTransactionAsync();
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var nestedActive = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseNested = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        var first = Task.Run(async () =>
        {
            await start.Task;
            await using var nested = await provider.BeginTransactionAsync();
            await using var handle = await manager.GetConnectionAsync(CancellationToken.None);
            Assert.That(await ExecuteScalarAsync(handle.Connection), Is.EqualTo(1));
            nestedActive.SetResult();
            await releaseNested.Task;
            await nested.CommitAsync();
        });
        var second = Task.Run(async () =>
        {
            await start.Task;
            await nestedActive.Task;
            var exception = Assert.ThrowsAsync<InvalidOperationException>(() => provider.BeginTransactionAsync());
            Assert.That(exception!.Message, Does.Contain("Task.WhenAll"));
        });

        start.SetResult();
        try
        {
            await second;
        }
        finally
        {
            releaseNested.SetResult();
        }
        await first;
        await using (var sequential = await provider.BeginTransactionAsync())
        {
            await sequential.CommitAsync();
        }
        await root.CommitAsync();
    }

    [Test]
    public async Task CapturedCompletedRootCannotJoinLaterRoot()
    {
        await using var manager = new PostgresTransactionManager(GetDataSource());
        await using var first = await manager.BeginTransactionAsync();
        var releaseCapturedFlow = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var capturedFlow = Task.Run(async () =>
        {
            await releaseCapturedFlow.Task;
            await using var transaction = await manager.BeginTransactionAsync();
        });

        await first.CommitAsync();
        await using var second = await manager.BeginTransactionAsync();
        releaseCapturedFlow.SetResult();

        Assert.ThrowsAsync<InvalidOperationException>(async () => await capturedFlow);
        Assert.DoesNotThrowAsync(async () => await second.CommitAsync());
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

    [Test]
    public async Task PostCommitHooksExecuteOnCommit()
    {
        await using var manager = new PostgresTransactionManager(GetDataSource());
        await using var transaction = await manager.BeginTransactionAsync();
        var hookExecuted = false;

        transaction.OnCommitted(_ =>
        {
            hookExecuted = true;
            return Task.CompletedTask;
        });

        await transaction.CommitAsync();

        Assert.That(hookExecuted, Is.True);
    }

    [Test]
    public async Task PostCommitHooksIgnoreCommitCancellationAfterCommitSucceeds()
    {
        await using var manager = new PostgresTransactionManager(GetDataSource());
        await using var transaction = await manager.BeginTransactionAsync();
        using var cancellationTokenSource = new CancellationTokenSource();
        var hookTokenCanceled = true;

        RegisterCancellationHook(transaction, cancellationTokenSource);

        transaction.OnCommitted(token =>
        {
            hookTokenCanceled = token.IsCancellationRequested;
            return Task.CompletedTask;
        });

        await transaction.CommitAsync(cancellationTokenSource.Token);

        Assert.That(hookTokenCanceled, Is.False);
    }

    [Test]
    public async Task PostCommitHooksExecuteInRegistrationOrder()
    {
        await using var manager = new PostgresTransactionManager(GetDataSource());
        await using var transaction = await manager.BeginTransactionAsync();
        var executions = new List<int>();

        transaction.OnCommitted(_ =>
        {
            executions.Add(1);
            return Task.CompletedTask;
        });

        transaction.OnCommitted(_ =>
        {
            executions.Add(2);
            return Task.CompletedTask;
        });

        transaction.OnCommitted(_ =>
        {
            executions.Add(3);
            return Task.CompletedTask;
        });

        await transaction.CommitAsync();

        Assert.That(executions, Is.EqualTo(ExpectedHookExecutionOrder));
    }

    [Test]
    public async Task OnCommittedThrowsWhenActionIsNull()
    {
        await using var manager = new PostgresTransactionManager(GetDataSource());
        await using var transaction = await manager.BeginTransactionAsync();

        AssertOnCommittedThrowsArgumentNull(transaction);
    }

    [Test]
    public async Task PostCommitHooksDoNotExecuteOnRollback()
    {
        await using var manager = new PostgresTransactionManager(GetDataSource());
        await using var transaction = await manager.BeginTransactionAsync();
        var hookExecuted = false;

        transaction.OnCommitted(_ =>
        {
            hookExecuted = true;
            return Task.CompletedTask;
        });

        await transaction.RollbackAsync();

        Assert.That(hookExecuted, Is.False);
    }

    [Test]
    public async Task PostCommitHooksDoNotExecuteOnDisposalWithoutCommit()
    {
        await using var manager = new PostgresTransactionManager(GetDataSource());
        var hookExecuted = false;

        await using (var transaction = await manager.BeginTransactionAsync())
        {
            transaction.OnCommitted(_ =>
            {
                hookExecuted = true;
                return Task.CompletedTask;
            });
        }

        Assert.That(hookExecuted, Is.False);
    }

    [Test]
    public async Task NestedPostCommitHooksDelegateToRootAndExecuteOnCommit()
    {
        await using var manager = new PostgresTransactionManager(GetDataSource());
        await using var outer = await manager.BeginTransactionAsync();
        var innerHookExecuted = false;

        await using (var inner = await manager.BeginTransactionAsync())
        {
            inner.OnCommitted(_ =>
            {
                innerHookExecuted = true;
                return Task.CompletedTask;
            });
            await inner.CommitAsync();
        }

        Assert.That(innerHookExecuted, Is.False, "Hook should not execute until the root transaction commits.");

        await outer.CommitAsync();

        Assert.That(innerHookExecuted, Is.True);
    }

    [Test]
    public async Task PostCommitHooksAreIsolatedFromEachOtherAndDoNotThrowAfterCommit()
    {
        var logger = new RecordingLogger<PostgresTransactionManager>();
        await using var manager = new PostgresTransactionManager(GetDataSource(), logger);
        await using var transaction = await manager.BeginTransactionAsync();
        var firstHookExecuted = false;
        var secondHookExecuted = false;

        transaction.OnCommitted(_ =>
        {
            firstHookExecuted = true;
            throw new InvalidOperationException("First hook failed");
        });

        transaction.OnCommitted(_ =>
        {
            secondHookExecuted = true;
            return Task.CompletedTask;
        });

        await transaction.CommitAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(firstHookExecuted, Is.True);
            Assert.That(secondHookExecuted, Is.True);
            Assert.That(logger.Entries, Has.Some.Matches<LogEntry>(entry =>
                entry.Level == LogLevel.Warning
                && entry.Exception is InvalidOperationException
                && entry.Message.Contains("Post-commit hook failed", StringComparison.Ordinal)
                && entry.Message.Contains("HookIndex=0", StringComparison.Ordinal)));
        }
    }

    [Test]
    public async Task PostCommitHookCancellationDoesNotThrowAfterCommitAndMutationStaysCommitted()
    {
        var tableName = "test_values_" + Guid.NewGuid().ToString("N");
        await InitializeTableAsync(tableName);
        await using var manager = new PostgresTransactionManager(GetDataSource());
        await using var transaction = await manager.BeginTransactionAsync();

        await using (var handle = await manager.GetConnectionAsync(CancellationToken.None))
        {
            await InsertValueAsync(handle.Connection, handle.Transaction, tableName, "committed");
        }

        transaction.OnCommitted(_ => throw new OperationCanceledException());

        await transaction.CommitAsync();

        Assert.That(await CountRowsAsync(tableName), Is.EqualTo(1));
    }

    private static async Task AssertCommitThrowsObjectDisposedAsync(Ashlar.Identity.Abstractions.Transactions.IAshlarTransaction transaction)
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

    private static void RegisterCancellationHook(
        Ashlar.Identity.Abstractions.Transactions.IAshlarTransaction transaction,
        CancellationTokenSource cancellationTokenSource)
    {
        transaction.OnCommitted(_ =>
        {
            cancellationTokenSource.Cancel();
            return Task.CompletedTask;
        });
    }

    private static void AssertOnCommittedThrowsArgumentNull(Ashlar.Identity.Abstractions.Transactions.IAshlarTransaction transaction)
    {
        try
        {
            // ReSharper disable once NullableWarningSuppressionIsUsed
            transaction.OnCommitted(null!);
        }
        catch (ArgumentNullException)
        {
            return;
        }

        Assert.Fail("Expected ArgumentNullException.");
    }

    private static async Task AssertCommitThrowsInvalidOperationAsync(Ashlar.Identity.Abstractions.Transactions.IAshlarTransaction transaction)
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

    private async Task InitializeTableAsync(string tableName)
    {
        await using var connection = await GetDataSource().OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = $"CREATE TABLE {QuoteIdentifier(tableName)} (value TEXT NOT NULL);";
        await command.ExecuteNonQueryAsync();
    }

    private async Task<int> CountRowsAsync(string tableName)
    {
        await using var connection = await GetDataSource().OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = $"SELECT COUNT(*) FROM {QuoteIdentifier(tableName)};";
        var result = await command.ExecuteScalarAsync();
        return Convert.ToInt32(result, System.Globalization.CultureInfo.InvariantCulture);
    }

    private static async Task InsertValueAsync(NpgsqlConnection connection, NpgsqlTransaction? transaction, string tableName, string value)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"INSERT INTO {QuoteIdentifier(tableName)} (value) VALUES ($1);";
        command.Parameters.AddWithValue(value);
        await command.ExecuteNonQueryAsync();
    }

    private static string QuoteIdentifier(string identifier)
    {
        return "\"" + identifier.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }
}
