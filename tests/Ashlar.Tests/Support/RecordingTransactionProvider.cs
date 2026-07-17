namespace Ashlar.Tests.Support;

internal sealed class RecordingTransactionProvider : IAshlarTransactionProvider
{
    public AshlarDurableTransactionProvider Compose(params object[] participants) => AshlarDurableTransactionProvider.Create(this, participants);
    public static implicit operator AshlarDurableTransactionProvider(RecordingTransactionProvider provider) => provider.Compose();
    private readonly AsyncLocal<RecordingTransaction?> _active = new();

    public RecordingTransactionProvider()
    {
        Transaction = CreateTransaction();
    }

    public RecordingTransaction Transaction { get; private set; }
    public int CommitCount { get; private set; }

    public Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default)
    {
        if (_active.Value is { } active)
        {
            return Task.FromResult<IAshlarTransaction>(new NestedTransaction(active));
        }

        Transaction = CreateTransaction();
        _active.Value = Transaction;
        Transaction.BeginCount++;
        return Task.FromResult<IAshlarTransaction>(Transaction);
    }

    private RecordingTransaction CreateTransaction() => new(committed =>
    {
        _active.Value = null;
        if (committed) CommitCount++;
    });
}

internal sealed class RecordingTransaction(Action<bool> onDisposed) : IAshlarTransaction
{
    private readonly List<Func<CancellationToken, Task>> _hooks = [];
    public int BeginCount { get; set; }
    public int CommitCount { get; private set; }
    public int DisposeCount { get; private set; }
    private bool _completed;
    private bool _committed;

    public async Task CommitAsync(CancellationToken cancellationToken = default)
    {
        if (_completed) return;
        _completed = true;
        _committed = true;
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
        _completed = true;
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
        onDisposed(_committed);
        return ValueTask.CompletedTask;
    }
}

internal sealed class NestedTransaction(RecordingTransaction root) : IAshlarTransaction
{
    public Task CommitAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
    public Task RollbackAsync(CancellationToken cancellationToken = default) => root.RollbackAsync(cancellationToken);
    public void OnCommitted(Func<CancellationToken, Task> action) => root.OnCommitted(action);
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
