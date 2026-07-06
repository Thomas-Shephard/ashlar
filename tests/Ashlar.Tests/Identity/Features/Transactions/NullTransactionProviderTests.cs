namespace Ashlar.Tests.Identity.Features.Transactions;

internal sealed class NullTransactionProviderTests
{
    private static readonly int[] ExpectedHookExecutionOrder = [1, 2, 3];

    [Test]
    public async Task BeginTransactionAsyncReturnsNoOpTransaction()
    {
        var provider = new NullTransactionProvider();

        await using var transaction = await provider.BeginTransactionAsync();

        await transaction.CommitAsync();

        Assert.That(transaction, Is.Not.Null);
    }

    [Test]
    public void BeginTransactionAsyncThrowsWhenCanceled()
    {
        using var cancellationTokenSource = new CancellationTokenSource();
        cancellationTokenSource.Cancel();
        var cancellationToken = cancellationTokenSource.Token;

        var provider = new NullTransactionProvider();

        Assert.ThrowsAsync<OperationCanceledException>(() => provider.BeginTransactionAsync(cancellationToken));
    }

    [Test]
    public void CommitAsyncThrowsWhenCanceled()
    {
        using var cancellationTokenSource = new CancellationTokenSource();
        cancellationTokenSource.Cancel();
        var cancellationToken = cancellationTokenSource.Token;

        Assert.ThrowsAsync<OperationCanceledException>(() => CommitTransactionAsync(cancellationToken));
    }

    [Test]
    public void RollbackAsyncThrowsWhenCanceled()
    {
        using var cancellationTokenSource = new CancellationTokenSource();
        cancellationTokenSource.Cancel();
        var cancellationToken = cancellationTokenSource.Token;

        Assert.ThrowsAsync<OperationCanceledException>(() => RollbackTransactionAsync(cancellationToken));
    }

    [Test]
    public async Task PostCommitHooksExecuteOnCommitAndDoNotThrowAfterCommit()
    {
        var provider = new NullTransactionProvider();
        await using var transaction = await provider.BeginTransactionAsync();
        var hookExecuted = false;
        var laterHookExecuted = false;

        transaction.OnCommitted(_ =>
        {
            hookExecuted = true;
            throw new InvalidOperationException("Hook failed");
        });

        transaction.OnCommitted(_ =>
        {
            laterHookExecuted = true;
            return Task.CompletedTask;
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.DoesNotThrowAsync(() => transaction.CommitAsync());
            Assert.That(hookExecuted, Is.True);
            Assert.That(laterHookExecuted, Is.True);
        }
    }

    [Test]
    public async Task PostCommitHooksIgnoreCommitCancellationAfterCommitSucceeds()
    {
        var provider = new NullTransactionProvider();
        await using var transaction = await provider.BeginTransactionAsync();
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
        var provider = new NullTransactionProvider();
        await using var transaction = await provider.BeginTransactionAsync();
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
        var provider = new NullTransactionProvider();
        await using var transaction = await provider.BeginTransactionAsync();

        AssertOnCommittedThrowsArgumentNull(transaction);
    }

    [Test]
    public async Task PostCommitHooksDoNotExecuteOnRollback()
    {
        var provider = new NullTransactionProvider();
        await using var transaction = await provider.BeginTransactionAsync();
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
    public async Task PostCommitHooksExecuteAtMostOnce()
    {
        var provider = new NullTransactionProvider();
        await using var transaction = await provider.BeginTransactionAsync();
        var hookExecutions = 0;

        transaction.OnCommitted(_ =>
        {
            hookExecutions++;
            return Task.CompletedTask;
        });

        await transaction.CommitAsync();

        await AssertCommitThrowsObjectDisposedAsync(transaction);
        Assert.That(hookExecutions, Is.EqualTo(1));
    }

    [Test]
    public async Task CommitAsyncThrowsAfterRollbackAndDoesNotExecuteHooks()
    {
        var provider = new NullTransactionProvider();
        await using var transaction = await provider.BeginTransactionAsync();
        var hookExecuted = false;

        transaction.OnCommitted(_ =>
        {
            hookExecuted = true;
            return Task.CompletedTask;
        });

        await transaction.RollbackAsync();

        await AssertCommitThrowsObjectDisposedAsync(transaction);
        Assert.That(hookExecuted, Is.False);
    }

    [Test]
    public async Task OnCommittedThrowsAfterCommit()
    {
        var provider = new NullTransactionProvider();
        await using var transaction = await provider.BeginTransactionAsync();

        await transaction.CommitAsync();

        AssertOnCommittedThrowsObjectDisposed(transaction);
    }

    private static async Task CommitTransactionAsync(CancellationToken cancellationToken)
    {
        await using var transaction = await new NullTransactionProvider().BeginTransactionAsync(CancellationToken.None);

        await transaction.CommitAsync(cancellationToken);
    }

    private static async Task RollbackTransactionAsync(CancellationToken cancellationToken)
    {
        await using var transaction = await new NullTransactionProvider().BeginTransactionAsync(CancellationToken.None);

        await transaction.RollbackAsync(cancellationToken);
    }

    private static void RegisterCancellationHook(IAshlarTransaction transaction, CancellationTokenSource cancellationTokenSource)
    {
        transaction.OnCommitted(_ =>
        {
            cancellationTokenSource.Cancel();
            return Task.CompletedTask;
        });
    }

    private static async Task AssertCommitThrowsObjectDisposedAsync(IAshlarTransaction transaction)
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

    private static void AssertOnCommittedThrowsObjectDisposed(IAshlarTransaction transaction)
    {
        try
        {
            transaction.OnCommitted(_ => Task.CompletedTask);
        }
        catch (ObjectDisposedException)
        {
            return;
        }

        Assert.Fail("Expected ObjectDisposedException.");
    }

    private static void AssertOnCommittedThrowsArgumentNull(IAshlarTransaction transaction)
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
}
