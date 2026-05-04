using Ashlar.Identity;

namespace Ashlar.Tests.Identity;

public sealed class NullTransactionProviderTests
{
    [Test]
    public async Task BeginTransactionAsyncReturnsNoOpTransaction()
    {
        var provider = new NullTransactionProvider();

        await using var transaction = await provider.BeginTransactionAsync();

        await transaction.CommitAsync();
        await transaction.RollbackAsync();

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
}
