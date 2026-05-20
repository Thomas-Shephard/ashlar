using Dapper;

namespace Ashlar.Postgres.Identity;

/// <summary>
/// Provides postgres bootstrap state repository behavior.
/// </summary>
/// <param name="connectionProvider">The connection provider value.</param>
public sealed class PostgresBootstrapStateRepository(IPostgresConnectionProvider connectionProvider) : IBootstrapStateRepository
{
    private readonly IPostgresConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));

    /// <summary>
    /// Performs the get bootstrap status <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<BootstrapStatus> GetBootstrapStatusAsync(CancellationToken cancellationToken = default)
    {
        const string sql = "SELECT is_initialized FROM ashlar_bootstrap_state WHERE id = 1";

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var isInitialized = await connectionHandle.Connection.QueryFirstOrDefaultAsync<bool?>(command);

            return isInitialized == true ? BootstrapStatus.Initialized : BootstrapStatus.Uninitialized;
        }
    }

    /// <summary>
    /// Performs the mark as initialized <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="initializedAt">The initialized at value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<bool> MarkAsInitializedAsync(Guid userId, DateTimeOffset initializedAt, CancellationToken cancellationToken = default)
    {
        const string sql = """
            INSERT INTO ashlar_bootstrap_state (id, is_initialized, initialized_at, initialized_by)
            VALUES (1, TRUE, @InitializedAt, @UserId)
            ON CONFLICT (id) DO UPDATE
            SET is_initialized = TRUE,
                initialized_at = EXCLUDED.initialized_at,
                initialized_by = EXCLUDED.initialized_by
            WHERE ashlar_bootstrap_state.is_initialized = FALSE
            """;

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new { UserId = userId, InitializedAt = initializedAt }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var rowsAffected = await connectionHandle.Connection.ExecuteAsync(command);

            return rowsAffected > 0;
        }
    }
}
