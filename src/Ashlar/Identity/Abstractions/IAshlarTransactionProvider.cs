namespace Ashlar.Identity.Abstractions;

/// <summary>
/// Provides a way to start a transaction in the Ashlar identity system.
/// </summary>
/// <remarks>
/// Providers define transaction scope at the persistence-provider boundary, typically one active durable
/// transaction per dependency-injection scope. Nested calls may either join the active transaction or reject
/// the request with an <see cref="InvalidOperationException"/>; callers should not rely on savepoint semantics.
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
