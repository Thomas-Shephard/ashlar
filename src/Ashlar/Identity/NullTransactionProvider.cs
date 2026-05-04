using Ashlar.Identity.Abstractions;

namespace Ashlar.Identity;

internal sealed class NullTransactionProvider : IAshlarTransactionProvider
{
    public Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult<IAshlarTransaction>(new NullTransaction());
    }

    private sealed class NullTransaction : IAshlarTransaction
    {
        public Task CommitAsync(CancellationToken cancellationToken = default)
        {
            return CompleteAsync(cancellationToken);
        }

        public Task RollbackAsync(CancellationToken cancellationToken = default)
        {
            return CompleteAsync(cancellationToken);
        }

        public ValueTask DisposeAsync()
        {
            return ValueTask.CompletedTask;
        }

        private static Task CompleteAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }
    }
}
