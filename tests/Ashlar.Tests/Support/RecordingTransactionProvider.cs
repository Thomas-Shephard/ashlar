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
    private readonly List<Func<CancellationToken, Task>> _hooks = [];
    public int BeginCount { get; set; }
    public int CommitCount { get; private set; }
    public int DisposeCount { get; private set; }

    public async Task CommitAsync(CancellationToken cancellationToken = default)
    {
        CommitCount++;
        foreach (var hook in _hooks)
        {
            try
            {
                await hook(CancellationToken.None);
            }
            catch (Exception)
            {
            }
        }
    }

    public Task RollbackAsync(CancellationToken cancellationToken = default)
    {
        _hooks.Clear();
        return Task.CompletedTask;
    }

    public void OnCommitted(Func<CancellationToken, Task> action)
    {
        _hooks.Add(action ?? throw new ArgumentNullException(nameof(action)));
    }

    public ValueTask DisposeAsync()
    {
        DisposeCount++;
        return ValueTask.CompletedTask;
    }
}
