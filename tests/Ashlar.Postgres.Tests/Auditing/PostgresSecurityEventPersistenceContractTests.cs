using Dapper;
using Npgsql;

namespace Ashlar.Postgres.Tests.Auditing;

internal sealed class PostgresSecurityEventPersistenceContractTests : SecurityEventPersistenceContractTests
{
    private PostgresContractDatabaseLease? _database;

    protected override async Task<IServiceProvider> CreateInitializedServiceProviderAsync()
    {
        _database = await PostgresContractDatabase.CreateInitializedServiceProviderAsync();
        return _database.ServiceProvider;
    }

    protected override async Task CleanupInitializedServiceProviderAsync()
    {
        if (_database != null)
        {
            await _database.DropDatabaseAsync();
            _database = null;
        }
    }

    protected override async Task<IReadOnlyList<SecurityEventStorageRecord>> ReadSecurityEventStorageRecordsAsync()
    {
        if (_database == null)
        {
            throw new InvalidOperationException("Contract database is not initialized.");
        }

        const string sql = """
            SELECT id, event_type, occurred_at, user_id, tenant_id, actor_user_id, session_id,
                   provider_type, provider_name, ip_address, user_agent, correlation_id, outcome, failure_reason,
                   properties::text AS properties_json
            FROM ashlar_security_events
            ORDER BY occurred_at, id
            """;

        await using var connection = new NpgsqlConnection(_database.ConnectionString);
        var rows = await connection.QueryAsync(sql);
        return rows.Select(row => new SecurityEventStorageRecord(
            (Guid)row.id,
            (string)row.event_type,
            (DateTimeOffset)row.occurred_at,
            (Guid?)row.user_id,
            (Guid?)row.tenant_id,
            (Guid?)row.actor_user_id,
            (Guid?)row.session_id,
            (string?)row.provider_type,
            (string?)row.provider_name,
            (string?)row.ip_address,
            (string?)row.user_agent,
            (string?)row.correlation_id,
            (string?)row.outcome,
            (string?)row.failure_reason,
            (string?)row.properties_json)).ToArray();
    }
}










