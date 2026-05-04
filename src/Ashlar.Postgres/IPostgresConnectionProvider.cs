using Npgsql;

namespace Ashlar.Postgres;

/// <summary>
/// Provides access to the scoped PostgreSQL connection and transaction.
/// </summary>
public interface IPostgresConnectionProvider
{
    /// <summary>
    /// Gets a handle to a connection. 
    /// If a transaction is active, the handle points to the shared connection and won't dispose it.
    /// If no transaction is active, the handle points to a fresh connection and will dispose it when finished.
    /// </summary>
    ValueTask<PostgresConnectionHandle> GetConnectionAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Gets the current transaction, if one is active.
    /// </summary>
    NpgsqlTransaction? CurrentTransaction { get; }
}
