namespace Ashlar.Identity.Abstractions;

/// <summary>
/// Provides a way to start a transaction in the Ashlar identity system.
/// </summary>
public interface IAshlarTransactionProvider
{
    /// <summary>
    /// Starts a new transaction.
    /// </summary>
    /// <returns>An <see cref="IAshlarTransaction"/> that can be committed or rolled back.</returns>
    Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default);
}
