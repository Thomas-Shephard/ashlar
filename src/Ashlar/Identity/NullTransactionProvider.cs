using Ashlar.Identity.Abstractions;

namespace Ashlar.Identity;

internal sealed class NullTransactionProvider : IAshlarTransactionProvider
{
    /// <summary>
    /// Performs the begin transaction <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
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
        /// Performs the commit <see langword="async" /> operation and returns the result.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token value.</param>
        /// <returns>The operation result.</returns>
        public async Task CommitAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ObjectDisposedException.ThrowIf(_disposed, this);

            var hooks = _hooks.ToArray();
            _hooks.Clear();
            _disposed = true;

            List<Exception>? hookExceptions = null;
            foreach (var hook in hooks)
            {
                try
                {
                    await hook(CancellationToken.None);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    (hookExceptions ??= []).Add(ex);
                }
            }

            if (hookExceptions != null)
            {
                throw new AggregateException("One or more post-commit hooks failed.", hookExceptions);
            }
        }

        /// <summary>
        /// Performs the rollback <see langword="async" /> operation and returns the result.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token value.</param>
        /// <returns>The operation result.</returns>
        public Task RollbackAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ObjectDisposedException.ThrowIf(_disposed, this);

            _hooks.Clear();
            _disposed = true;
            return Task.CompletedTask;
        }

        /// <summary>
        /// Performs the on committed operation and returns the result.
        /// </summary>
        /// <param name="action">The action value.</param>
        public void OnCommitted(Func<CancellationToken, Task> action)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _hooks.Add(action ?? throw new ArgumentNullException(nameof(action)));
        }

        /// <summary>
        /// Performs the dispose <see langword="async" /> operation and returns the result.
        /// </summary>
        /// <returns>The operation result.</returns>
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
