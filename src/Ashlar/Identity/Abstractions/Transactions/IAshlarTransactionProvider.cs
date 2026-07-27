using System.Runtime.ExceptionServices;

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
    private const string TransactionCompletedMessage = "The transaction has already completed.";
    private readonly IAshlarTransactionProvider _provider;
    private readonly HashSet<object> _participants;
    private readonly AsyncLocal<TransactionBoundary?> _active = new();
    private readonly AsyncLocal<object?> _scope = new();

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
            var parent = _scope.Value;
            var lease = new object();
            if (active.Busy || active.Terminal || !active.TryAcquire(parent!, lease))
                throw new InvalidOperationException("The durable transaction is already starting, completing, or owned by another inherited async flow. Await transaction scopes sequentially; do not use Task.WhenAll for work sharing one provider connection.");
            _scope.Value = lease;
            return Task.FromResult<IAshlarTransaction>(new NestedTransaction(active, _scope, parent!, lease));
        }

        return BeginNewBoundaryAsync(cancellationToken);
    }

    private Task<IAshlarTransaction> BeginNewBoundaryAsync(CancellationToken cancellationToken)
    {
        var lease = new object();
        var boundary = new TransactionBoundary(_active, _scope, lease) { Busy = true };
        _active.Value = boundary;
        _scope.Value = lease;
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
            return new RootTransaction(boundary, boundary.RootLease);
        }
        catch
        {
            boundary.Completed = true;
            throw;
        }
    }

    private sealed class TransactionBoundary(
        AsyncLocal<TransactionBoundary?> active,
        AsyncLocal<object?> scope,
        object owner)
    {
        private object _owner = owner;
        public object RootLease { get; } = owner;
        public AsyncLocal<TransactionBoundary?> Active { get; } = active;
        public AsyncLocal<object?> Scope { get; } = scope;
        public IAshlarTransaction Transaction { get; set; } = null!;
        public bool Completed { get; set; }
        private int _busy;
        public bool Busy
        {
            get => Volatile.Read(ref _busy) != 0;
            set => Volatile.Write(ref _busy, value ? 1 : 0);
        }
        public bool Terminal { get; set; }
        public bool RollbackOnly { get; set; }
        private Exception? _rollbackCause;
        public Exception? RollbackCause => Volatile.Read(ref _rollbackCause);

        public void Exit() => Volatile.Write(ref _busy, 0);
        public bool TryAcquire(object parent, object lease) => ReferenceEquals(Interlocked.CompareExchange(ref _owner, lease, parent), parent);
        public bool IsOwner(object? lease) => ReferenceEquals(Volatile.Read(ref _owner), lease);
        public void Release(object parent) => Interlocked.Exchange(ref _owner, parent);
        public void MarkRollbackOnly(string message)
        {
            RollbackOnly = true;
            Interlocked.CompareExchange(
                ref _rollbackCause,
                ExceptionDispatchInfo.SetCurrentStackTrace(new InvalidOperationException(message)),
                null);
        }

        public void OnCommitted(Func<CancellationToken, Task> action)
        {
            ArgumentNullException.ThrowIfNull(action);
            Transaction.OnCommitted(async cancellationToken =>
            {
                Terminal = true;
                Active.Value = null;
                Scope.Value = null;
                await action(cancellationToken).ConfigureAwait(false);
            });
        }
    }

    private sealed class RootTransaction(TransactionBoundary boundary, object lease) : IAshlarTransaction
    {
        private readonly object _terminalLease = new();
        private readonly object _completedLease = new();
        private readonly object _disposeLease = new();
        private readonly object _hookLease = new();
        private bool _disposed;

        public async Task CommitAsync(CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            cancellationToken.ThrowIfCancellationRequested();
            if (!boundary.TryAcquire(lease, _terminalLease)) throw new InvalidOperationException(TransactionCompletedMessage);
            if (boundary.RollbackOnly)
            {
                boundary.Release(lease);
                throw new InvalidOperationException(
                    "The transaction cannot be committed because a nested transaction rolled back or was disposed without CommitAsync. See the inner exception for the first rollback-only origin.",
                    boundary.RollbackCause);
            }
            boundary.Terminal = true;
            boundary.Busy = true;
            try
            {
                await boundary.Transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                boundary.Release(_completedLease);
                boundary.Exit();
            }
        }

        public async Task RollbackAsync(CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            cancellationToken.ThrowIfCancellationRequested();
            if (!boundary.TryAcquire(lease, _terminalLease)) throw new InvalidOperationException(TransactionCompletedMessage);
            boundary.MarkRollbackOnly("The root transaction was explicitly rolled back.");
            boundary.Terminal = true;
            boundary.Busy = true;
            try
            {
                await boundary.Transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                boundary.Release(_completedLease);
                boundary.Exit();
            }
        }
        public void OnCommitted(Func<CancellationToken, Task> action)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (!boundary.TryAcquire(lease, _hookLease)) throw new InvalidOperationException(TransactionCompletedMessage);
            try
            {
                boundary.OnCommitted(action);
            }
            finally
            {
                boundary.Release(lease);
            }
        }

        public async ValueTask DisposeAsync()
        {
            if (_disposed) return;
            var expectedLease = boundary.Terminal ? _completedLease : lease;
            if (boundary.Busy || !boundary.TryAcquire(expectedLease, _disposeLease))
            {
                throw new InvalidOperationException("The transaction cannot be disposed while an operation is in progress.");
            }
            boundary.Busy = true;
            _disposed = true;
            boundary.Terminal = true;
            try
            {
                await boundary.Transaction.DisposeAsync().ConfigureAwait(false);
                boundary.Completed = true;
            }
            finally
            {
                boundary.Exit();
            }
        }

    }

    private sealed class NestedTransaction(
        TransactionBoundary boundary,
        AsyncLocal<object?> scope,
        object parent,
        object lease) : IAshlarTransaction
    {
        private readonly object _hookLease = new();
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
            boundary.MarkRollbackOnly("A nested transaction explicitly called RollbackAsync.");
            _completed = true;
            return Task.CompletedTask;
        }
        public void OnCommitted(Func<CancellationToken, Task> action)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_completed || !boundary.TryAcquire(lease, _hookLease)) throw new InvalidOperationException(TransactionCompletedMessage);
            try
            {
                boundary.OnCommitted(action);
            }
            finally
            {
                boundary.Release(lease);
            }
        }

        public ValueTask DisposeAsync()
        {
            if (_disposed) return ValueTask.CompletedTask;
            if (!boundary.IsOwner(lease)) throw new InvalidOperationException("The transaction scope is no longer active.");
            if (!_completed) boundary.MarkRollbackOnly("A nested transaction was disposed without CommitAsync or RollbackAsync.");
            boundary.Release(parent);
            _disposed = true;
            scope.Value = parent;
            return ValueTask.CompletedTask;
        }

        private void EnsureActive()
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_completed || !boundary.IsOwner(lease)) throw new InvalidOperationException(TransactionCompletedMessage);
        }
    }
}

internal sealed record AshlarDurableTransactionParticipantRegistration(Type ServiceType);
