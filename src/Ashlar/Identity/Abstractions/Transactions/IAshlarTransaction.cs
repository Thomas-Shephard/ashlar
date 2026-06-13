namespace Ashlar.Identity.Abstractions.Transactions;

/// <summary>
/// Represents an active transaction in the Ashlar identity system.
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
    /// <returns>A task that completes after durable changes and commit hooks have finished.</returns>
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
    /// Registered actions are executed after the transaction commit has completed and receive a cancellation token
    /// that is not linked to the caller's commit token. Non-cancellation failures are isolated from later actions
    /// and reported from <see cref="CommitAsync"/> as an <see cref="AggregateException"/> after all registered
    /// actions have been attempted. Hooks must not run when the provider transaction rolls back.
    /// </remarks>
    void OnCommitted(Func<CancellationToken, Task> action);
}
