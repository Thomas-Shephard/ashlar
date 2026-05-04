namespace Ashlar.Identity.Abstractions;

/// <summary>
/// Represents an active transaction in the Ashlar identity system.
/// </summary>
public interface IAshlarTransaction : IAsyncDisposable
{
    /// <summary>
    /// Commits the transaction.
    /// </summary>
    Task CommitAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Rolls back the transaction.
    /// </summary>
    Task RollbackAsync(CancellationToken cancellationToken = default);
}
