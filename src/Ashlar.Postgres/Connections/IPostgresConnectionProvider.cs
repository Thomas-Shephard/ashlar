namespace Ashlar.Postgres.Connections;

/// <summary>
/// Provides access to the scoped PostgreSQL connection and transaction.
/// </summary>
public interface IPostgresConnectionProvider
{
    /// <summary>
    /// Gets a handle to a connection. 
    /// If a transaction is active, the handle points to the shared connection and includes the active transaction.
    /// If no transaction is active, the handle points to a fresh connection and will dispose it when finished.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    /// <remarks>
    /// Note: Npgsql connections and transactions are not thread-safe. Concurrent operations on the same 
    /// connection handle (especially within a transaction) are not supported and will lead to errors.
    /// </remarks>
    ValueTask<PostgresConnectionHandle> GetConnectionAsync(CancellationToken cancellationToken);
}
