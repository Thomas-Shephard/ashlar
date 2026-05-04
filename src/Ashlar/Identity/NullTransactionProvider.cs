using Ashlar.Identity.Abstractions;

namespace Ashlar.Identity;

internal sealed class NullTransactionProvider : IAshlarTransactionProvider
{
    public Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult<IAshlarTransaction>(new NullTransaction());
    }

    private sealed class NullTransaction : IAshlarTransaction
    {
        public Task CommitAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task RollbackAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
