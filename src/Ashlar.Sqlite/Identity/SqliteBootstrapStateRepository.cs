namespace Ashlar.Sqlite.Identity;

internal sealed class SqliteBootstrapStateRepository(ISqliteConnectionProvider connectionProvider) : IBootstrapStateRepository
{
    private readonly ISqliteConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));

    public async Task<BootstrapStatus> GetBootstrapStatusAsync(CancellationToken cancellationToken = default)
    {
        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = "SELECT is_initialized FROM ashlar_bootstrap_state WHERE id = 1;";

        var result = await command.ExecuteScalarAsync(cancellationToken);
        return Convert.ToInt32(result ?? 0, System.Globalization.CultureInfo.InvariantCulture) == 1
            ? BootstrapStatus.Initialized
            : BootstrapStatus.Uninitialized;
    }

    public async Task<bool> MarkAsInitializedAsync(Guid userId, DateTimeOffset initializedAt, CancellationToken cancellationToken = default)
    {
        const string sql = """
            INSERT INTO ashlar_bootstrap_state (id, is_initialized, initialized_at, initialized_by)
            VALUES (1, 1, $initializedAt, $userId)
            ON CONFLICT(id) DO UPDATE
            SET is_initialized = 1,
                initialized_at = excluded.initialized_at,
                initialized_by = excluded.initialized_by
            WHERE ashlar_bootstrap_state.is_initialized = 0;
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddGuidParameter("$userId", userId);
        command.AddDateTimeOffsetParameter("$initializedAt", initializedAt);

        return await command.ExecuteNonQueryAsync(cancellationToken) > 0;
    }
}
