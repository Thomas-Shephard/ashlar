using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Dapper;

namespace Ashlar.Postgres;

public sealed class PostgresBootstrapStateRepository(IPostgresConnectionProvider connectionProvider) : IBootstrapStateRepository
{
    private readonly IPostgresConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));

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
