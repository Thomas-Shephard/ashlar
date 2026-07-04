namespace Ashlar.Identity.Abstractions.Transactions;

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
    /// <param name="cancellationToken">A token that can cancel transaction creation.</param>
    /// <returns>An active transaction that must be disposed by the caller.</returns>
    /// <exception cref="InvalidOperationException">Thrown if a transaction is already in progress.</exception>
    Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Identifies an Ashlar transaction provider whose transactions roll back durable repository writes.
/// </summary>
/// <remarks>
/// Flows that must coordinate multiple durable mutations atomically can require this marker before starting work.
/// The provider must either join nested transaction scopes to the same durable transaction or reject nested scopes.
/// </remarks>
public interface IAshlarDurableTransactionProvider : IAshlarTransactionProvider;
