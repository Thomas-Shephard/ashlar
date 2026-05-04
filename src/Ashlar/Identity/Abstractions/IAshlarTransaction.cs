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
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    Task CommitAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Rolls back the transaction.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    Task RollbackAsync(CancellationToken cancellationToken = default);
}
