namespace Ashlar.Identity.Abstractions.Transactions;

/// <summary>
/// Low-level transaction contract implemented by durable Ashlar persistence providers.
/// </summary>
/// <remarks>
/// Providers define transaction scope at the persistence-provider boundary, typically one active durable
/// transaction per dependency-injection scope. Nested calls must join the active transaction so repository
/// mutations and durable audit share one commit or rollback; callers must not rely on savepoint semantics.
/// Concurrent independent roots in the same dependency-injection scope are not supported.
/// </remarks>
public interface IAshlarTransactionProvider
{
    /// <summary>
    /// Starts a root transaction or joins the active transaction propagated in the current <see langword="async" /> flow.
    /// </summary>
    /// <param name="cancellationToken">A token that can cancel transaction creation.</param>
    /// <returns>An active transaction that must be disposed by the caller.</returns>
    Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Ashlar-owned durable transaction composition binding a transaction provider to its enlisted persistence participants.
/// </summary>
/// <remarks>
/// Persistence packages register their transaction provider and enlisted participants through Ashlar's dependency-injection
/// extensions. Ashlar creates this sealed composition and rejects durable mutation services when any participant is absent.
/// Nested calls are joined by this Ashlar-owned wrapper, so a custom provider cannot split nested mutation and audit work
/// into independently committable transactions. A completed root must be disposed before another root begins, except
/// from a post-commit callback after the provider has cleared its durable transaction state.
/// </remarks>
public sealed class AshlarDurableTransactionProvider : IAshlarTransactionProvider
{
    private readonly IAshlarTransactionProvider _provider;
    private readonly HashSet<object> _participants;
    private readonly AsyncLocal<TransactionBoundary?> _active = new();

    private AshlarDurableTransactionProvider(IAshlarTransactionProvider provider, IEnumerable<object> participants)
    {
        _provider = provider;
        _participants = new HashSet<object>(participants, ReferenceEqualityComparer.Instance);
    }

    /// <summary>
    /// Creates a durable composition for one provider transaction boundary and every repository, audit sink, and durable fan-out handler enlisted in it.
    /// </summary>
    /// <param name="provider">The provider transaction implementation.</param>
    /// <param name="participants">The participant instances whose writes use that transaction.</param>
    /// <returns>A sealed Ashlar durable transaction composition.</returns>
    internal static AshlarDurableTransactionProvider Create(IAshlarTransactionProvider provider, params object[] participants)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(participants);
        if (participants.Any(static participant => participant is null)) throw new ArgumentException("Durable transaction participants cannot contain null.", nameof(participants));
        return new AshlarDurableTransactionProvider(provider, participants);
    }

    /// <summary>Returns whether the exact participant instance is enlisted in this composition.</summary>
    /// <param name="participant">The repository, persistent audit sink, or durable fan-out handler to verify.</param>
    /// <returns><see langword="true"/> when the same instance was included when the composition was created.</returns>
    public bool IncludesParticipant(object participant)
    {
        ArgumentNullException.ThrowIfNull(participant);
        return _participants.Contains(participant);
    }

    /// <inheritdoc />
    public Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default)
    {
        var active = _active.Value;
        if (active is { Completed: false })
        {
            if (active.Busy || active.Terminal) throw new InvalidOperationException("The active transaction boundary is not ready to accept more work.");
            return Task.FromResult<IAshlarTransaction>(new NestedTransaction(active));
        }

        return BeginNewBoundaryAsync(cancellationToken);
    }

    private Task<IAshlarTransaction> BeginNewBoundaryAsync(CancellationToken cancellationToken)
    {
        var boundary = new TransactionBoundary { Active = _active, Busy = true };
        _active.Value = boundary;
        try
        {
            return BeginRootTransactionAsync(boundary, _provider.BeginTransactionAsync(cancellationToken));
        }
        catch
        {
            boundary.Completed = true;
            throw;
        }
    }

    private static async Task<IAshlarTransaction> BeginRootTransactionAsync(
        TransactionBoundary boundary,
        Task<IAshlarTransaction> transaction)
    {
        try
        {
            boundary.Transaction = await transaction.ConfigureAwait(false)
                ?? throw new InvalidOperationException("The transaction provider returned no transaction.");
            boundary.Busy = false;
            return new RootTransaction(boundary);
        }
        catch
        {
            boundary.Completed = true;
            throw;
        }
    }

    private sealed class TransactionBoundary
    {
        public required AsyncLocal<TransactionBoundary?> Active { get; init; }
        public IAshlarTransaction Transaction { get; set; } = null!;
        public bool Completed { get; set; }
        public bool Busy { get; set; }
        public bool Terminal { get; set; }
        public bool RollbackOnly { get; set; }

        public void OnCommitted(Func<CancellationToken, Task> action)
        {
            ArgumentNullException.ThrowIfNull(action);
            Transaction.OnCommitted(async cancellationToken =>
            {
                Terminal = true;
                Active.Value = null;
                await action(cancellationToken).ConfigureAwait(false);
            });
        }
    }

    private sealed class RootTransaction(TransactionBoundary boundary) : IAshlarTransaction
    {
        private bool _disposed;

        public async Task CommitAsync(CancellationToken cancellationToken = default)
        {
            EnsureActive();
            cancellationToken.ThrowIfCancellationRequested();
            if (boundary.RollbackOnly) throw new InvalidOperationException("The transaction cannot be committed because it has been marked for rollback by a nested participant.");
            boundary.Busy = true;
            try
            {
                await boundary.Transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                boundary.Terminal = true;
                boundary.Busy = false;
            }
        }

        public async Task RollbackAsync(CancellationToken cancellationToken = default)
        {
            EnsureActive();
            cancellationToken.ThrowIfCancellationRequested();
            boundary.RollbackOnly = true;
            boundary.Busy = true;
            try
            {
                await boundary.Transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                boundary.Terminal = true;
                boundary.Busy = false;
            }
        }
        public void OnCommitted(Func<CancellationToken, Task> action)
        {
            EnsureActive();
            boundary.OnCommitted(action);
        }

        public async ValueTask DisposeAsync()
        {
            if (_disposed) return;
            if (boundary.Busy) throw new InvalidOperationException("The transaction cannot be disposed while an operation is in progress.");
            _disposed = true;
            boundary.Terminal = true;
            boundary.Busy = true;
            try
            {
                await boundary.Transaction.DisposeAsync().ConfigureAwait(false);
                boundary.Completed = true;
            }
            finally
            {
                boundary.Busy = false;
            }
        }

        private void EnsureActive()
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (boundary.Terminal || boundary.Busy) throw new InvalidOperationException("The transaction has already completed.");
        }
    }

    private sealed class NestedTransaction(TransactionBoundary boundary) : IAshlarTransaction
    {
        private bool _completed;
        private bool _disposed;
        public Task CommitAsync(CancellationToken cancellationToken = default)
        {
            EnsureActive();
            cancellationToken.ThrowIfCancellationRequested();
            _completed = true;
            return Task.CompletedTask;
        }

        public Task RollbackAsync(CancellationToken cancellationToken = default)
        {
            EnsureActive();
            cancellationToken.ThrowIfCancellationRequested();
            boundary.RollbackOnly = true;
            _completed = true;
            return Task.CompletedTask;
        }
        public void OnCommitted(Func<CancellationToken, Task> action)
        {
            EnsureActive();
            boundary.OnCommitted(action);
        }

        public ValueTask DisposeAsync()
        {
            if (_disposed) return ValueTask.CompletedTask;
            _disposed = true;
            if (!_completed) boundary.RollbackOnly = true;
            return ValueTask.CompletedTask;
        }

        private void EnsureActive()
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_completed || boundary.Busy || boundary.Terminal || boundary.Completed) throw new InvalidOperationException("The transaction has already completed.");
        }
    }
}

internal sealed record AshlarDurableTransactionParticipantRegistration(Type ServiceType);
