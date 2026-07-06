namespace Ashlar.Tests.Support;

internal sealed class RecordingTransactionProvider : IAshlarTransactionProvider
{
    public RecordingTransaction Transaction { get; } = new();

    public Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default)
    {
        Transaction.BeginCount++;
        return Task.FromResult<IAshlarTransaction>(Transaction);
    }
}

internal sealed class RecordingTransaction : IAshlarTransaction
{
    public int BeginCount { get; set; }
    public int CommitCount { get; private set; }
    public int DisposeCount { get; private set; }

    public Task CommitAsync(CancellationToken cancellationToken = default)
    {
        CommitCount++;
        return Task.CompletedTask;
    }

    public Task RollbackAsync(CancellationToken cancellationToken = default)
    {
        return Task.CompletedTask;
    }

    public void OnCommitted(Func<CancellationToken, Task> action)
    {
    }

    public ValueTask DisposeAsync()
    {
        DisposeCount++;
        return ValueTask.CompletedTask;
    }
}
