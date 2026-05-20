using Microsoft.Data.Sqlite;

namespace Ashlar.Sqlite.Tests.Auditing;

internal sealed class SqliteSecurityEventPersistenceContractTests : SecurityEventPersistenceContractTests
{
    private SqliteContractDatabase? _database;

    protected override async Task<IServiceProvider> CreateInitializedServiceProviderAsync()
    {
        _database = await SqliteContractDatabase.CreateAsync();
        return _database.ServiceProvider;
    }

    protected override Task CleanupInitializedServiceProviderAsync()
    {
        _database?.Delete();
        _database = null;
        return Task.CompletedTask;
    }

    protected override async Task<IReadOnlyList<SecurityEventStorageRecord>> ReadSecurityEventStorageRecordsAsync()
    {
        if (_database == null)
        {
            throw new InvalidOperationException("Contract database is not initialized.");
        }

        var records = new List<SecurityEventStorageRecord>();
        await using var connection = new SqliteConnection(_database.ConnectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, event_type, occurred_at, user_id, tenant_id, actor_user_id, session_id,
                   provider_type, provider_name, ip_address, user_agent, correlation_id, outcome, failure_reason,
                   properties
            FROM ashlar_security_events
            ORDER BY occurred_at, id;
            """;

        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            records.Add(new SecurityEventStorageRecord(
                reader.GetGuidFromText("id"),
                reader.GetString(reader.GetOrdinal("event_type")),
                reader.GetDateTimeOffsetFromText("occurred_at"),
                reader.GetNullableGuidFromText("user_id"),
                reader.GetNullableGuidFromText("tenant_id"),
                reader.GetNullableGuidFromText("actor_user_id"),
                reader.GetNullableGuidFromText("session_id"),
                reader.GetNullableString("provider_type"),
                reader.GetNullableString("provider_name"),
                reader.GetNullableString("ip_address"),
                reader.GetNullableString("user_agent"),
                reader.GetNullableString("correlation_id"),
                reader.GetNullableString("outcome"),
                reader.GetNullableString("failure_reason"),
                reader.GetNullableString("properties")));
        }

        return records;
    }
}
