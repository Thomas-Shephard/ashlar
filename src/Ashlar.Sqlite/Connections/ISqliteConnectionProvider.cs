namespace Ashlar.Sqlite.Connections;

/// <summary>
/// Provides access to the scoped SQLite connection and transaction.
/// </summary>
public interface ISqliteConnectionProvider
{
    /// <summary>
    /// Gets a handle to a SQLite connection.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    /// <remarks>
    /// If a transaction is active, the handle points to the shared scoped connection and includes the active
    /// transaction. If no transaction is active, the handle owns a fresh connection and disposes it when finished.
    /// SQLite connections and transactions are not thread-safe for concurrent operations.
    /// </remarks>
    ValueTask<SqliteConnectionHandle> GetConnectionAsync(CancellationToken cancellationToken);
}
