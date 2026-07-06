namespace Ashlar.Identity.Features.Transactions;

internal sealed class NullTransactionProvider : IAshlarTransactionProvider
{
    /// <summary>
    /// Starts an in-memory no-op transaction scope.
    /// </summary>
    /// <param name="cancellationToken">A token observed before creating the transaction.</param>
    /// <returns>A no-op transaction that still runs post-commit hooks.</returns>
    public Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult<IAshlarTransaction>(new NullTransaction());
    }

    private sealed class NullTransaction : IAshlarTransaction
    {
        private readonly List<Func<CancellationToken, Task>> _hooks = [];
        private bool _disposed;

        /// <summary>
        /// Marks the no-op transaction committed and runs post-commit hooks.
        /// </summary>
        /// <param name="cancellationToken">A token observed before hooks are run.</param>
        /// <returns>A task that completes after post-commit hooks have been attempted.</returns>
        public async Task CommitAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ObjectDisposedException.ThrowIf(_disposed, this);

            var hooks = _hooks.ToArray();
            _hooks.Clear();
            _disposed = true;

            foreach (var hook in hooks)
            {
                try
                {
                    await hook(CancellationToken.None);
                }
                catch (Exception)
                {
                    // Null provider has no logger; durable no-op commit semantics still match real providers.
                }
            }
        }

        /// <summary>
        /// Clears pending post-commit hooks without running them.
        /// </summary>
        /// <param name="cancellationToken">A token observed before rollback.</param>
        /// <returns>A completed task after the no-op transaction is marked complete.</returns>
        public Task RollbackAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ObjectDisposedException.ThrowIf(_disposed, this);

            _hooks.Clear();
            _disposed = true;
            return Task.CompletedTask;
        }

        /// <summary>
        /// Registers a callback to run when the no-op transaction commits.
        /// </summary>
        /// <param name="action">Callback to run after a successful commit.</param>
        public void OnCommitted(Func<CancellationToken, Task> action)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _hooks.Add(action ?? throw new ArgumentNullException(nameof(action)));
        }

        /// <summary>
        /// Disposes the no-op transaction and clears pending hooks.
        /// </summary>
        /// <returns>A completed value task.</returns>
        public ValueTask DisposeAsync()
        {
            if (_disposed)
            {
                return ValueTask.CompletedTask;
            }

            _hooks.Clear();
            _disposed = true;
            return ValueTask.CompletedTask;
        }
    }
}
