namespace Ashlar.Identity.Abstractions.Transactions;

/// <summary>
/// Low-level transaction handle returned by an Ashlar persistence provider.
/// </summary>
/// <remarks>
/// Callers MUST ensure <see cref="IAsyncDisposable.DisposeAsync"/> is called (e.g., via an <c>await using</c> block) 
/// to release the underlying database connection and associated resources. This is required even after 
/// calling <see cref="CommitAsync"/> or <see cref="RollbackAsync"/>. Disposing an uncommitted transaction must
/// leave durable state uncommitted; providers may implement that by rolling back or by marking the ambient
/// transaction rollback-only when this transaction joined an existing provider transaction.
/// </remarks>
public interface IAshlarTransaction : IAsyncDisposable
{
    /// <summary>
    /// Commits the transaction.
    /// </summary>
    /// <param name="cancellationToken">A token that can cancel the commit attempt.</param>
    /// <returns>A task that completes after durable changes and post-commit hooks have been attempted.</returns>
    Task CommitAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Rolls back the transaction.
    /// </summary>
    /// <param name="cancellationToken">A token that can cancel the rollback attempt.</param>
    /// <returns>A task that completes after pending durable changes have been abandoned.</returns>
    Task RollbackAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Registers an action to be executed only after the transaction has successfully committed.
    /// Actions are executed in the order they were registered.
    /// </summary>
    /// <param name="action">Callback to run after a successful commit.</param>
    /// <remarks>
    /// Registered actions are executed after the durable commit has completed and the provider has released its active
    /// transaction state. They receive a cancellation token that is not linked to the caller's commit token. Hook failures
    /// are isolated from later actions and must not make <see cref="CommitAsync"/> report that a durable commit failed.
    /// Providers should log or otherwise report hook failures. Hooks must not run when the transaction rolls back.
    /// </remarks>
    void OnCommitted(Func<CancellationToken, Task> action);
}
