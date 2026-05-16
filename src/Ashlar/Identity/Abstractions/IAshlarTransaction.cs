namespace Ashlar.Identity.Abstractions;

/// <summary>
/// Represents an active transaction in the Ashlar identity system.
/// </summary>
/// <remarks>
/// Callers MUST ensure <see cref="IAsyncDisposable.DisposeAsync"/> is called (e.g., via an <c>await using</c> block) 
/// to release the underlying database connection and associated resources. This is required even after 
/// calling <see cref="CommitAsync"/> or <see cref="RollbackAsync"/>.
/// </remarks>
public interface IAshlarTransaction : IAsyncDisposable
{
    /// <summary>
    /// Commits the transaction.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task CommitAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Rolls back the transaction.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task RollbackAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Registers an action to be executed only after the transaction has successfully committed.
    /// Actions are executed in the order they were registered.
    /// </summary>
    /// <param name="action">The action value.</param>
    /// <remarks>
    /// Registered actions are executed after the transaction commit has completed and receive a cancellation token
    /// that is not linked to the caller's commit token. Non-cancellation failures are isolated from later actions
    /// and reported from <see cref="CommitAsync"/> as an <see cref="AggregateException"/> after all registered
    /// actions have been attempted.
    /// </remarks>
    void OnCommitted(Func<CancellationToken, Task> action);
}
