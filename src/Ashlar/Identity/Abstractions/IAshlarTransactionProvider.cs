namespace Ashlar.Identity.Abstractions;

/// <summary>
/// Provides a way to start a transaction in the Ashlar identity system.
/// </summary>
/// <remarks>
/// Only one active transaction is supported per provider instance (typically per scope). 
/// Attempting to start a new transaction while one is already in progress may throw an <see cref="InvalidOperationException"/>.
/// </remarks>
public interface IAshlarTransactionProvider
{
    /// <summary>
    /// Starts a new transaction.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    /// <exception cref="InvalidOperationException">Thrown if a transaction is already in progress.</exception>
    Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default);
}
