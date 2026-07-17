namespace Ashlar.Tests.Support;

internal sealed class NullTransactionProvider : IAshlarTransactionProvider
{
    public Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult<IAshlarTransaction>(new Transaction());
    }

    private sealed class Transaction : IAshlarTransaction
    {
        private readonly List<Func<CancellationToken, Task>> _hooks = [];

        public async Task CommitAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            foreach (var hook in _hooks) await hook(CancellationToken.None);
            _hooks.Clear();
        }

        public Task RollbackAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _hooks.Clear();
            return Task.CompletedTask;
        }

        public void OnCommitted(Func<CancellationToken, Task> action) =>
            _hooks.Add(action ?? throw new ArgumentNullException(nameof(action)));

        public ValueTask DisposeAsync()
        {
            _hooks.Clear();
            return ValueTask.CompletedTask;
        }
    }
}
