using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using System.Globalization;

namespace Ashlar.Sqlite.Tests.Webhooks;

internal sealed class SqliteSecurityEventWebhookOutboxCleanupContractTests : SecurityEventWebhookOutboxCleanupContractTests
{
    private SqliteContractDatabase? _database;

    protected override async Task<IServiceProvider> CreateInitializedServiceProviderAsync()
    {
        _database = await SqliteContractDatabase.CreateAsync(services =>
        {
            services.AddSingleton<TimeProvider>(new FakeTimeProvider(CleanupNow));
            services.AddAshlarSqliteSecurityEventWebhookOutbox();
            services.AddAshlarSqliteCleanup(options =>
            {
                options.BatchSize = 2;
                options.MaxBatchesPerRun = 1;
            });
        });
        return _database.ServiceProvider;
    }

    protected override Task CleanupInitializedServiceProviderAsync()
    {
        _database?.Delete();
        _database = null;
        return Task.CompletedTask;
    }

    protected override async Task SeedWebhookOutboxCleanupRowAsync(SeedWebhookCleanupRow row)
    {
        await using var connection = new Microsoft.Data.Sqlite.SqliteConnection(_database!.ConnectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO ashlar_security_event_webhook_outbox (
                id, endpoint_name, uri, event_id, event_type, outcome, occurred_at, timeout_ms, body, headers,
                created_at, available_at, sent_at, failed_at, discarded_at, locked_by, locked_until, last_attempt_at, attempt_count, last_error)
            VALUES (
                $id, $endpointName, 'https://example.test/security-events', $eventId, 'security.test', 'success', $createdAt, 1000, $body, '{}',
                $createdAt, $availableAt, $sentAt, $failedAt, $discardedAt, $lockedBy, $lockedUntil, $failedAt, $attemptCount, $lastError);
            """;
        command.AddGuidParameter("$id", Guid.NewGuid());
        command.AddParameter("$endpointName", row.EndpointName);
        command.AddGuidParameter("$eventId", row.EventId);
        command.AddDateTimeOffsetParameter("$createdAt", row.CreatedAt);
        command.AddDateTimeOffsetParameter("$availableAt", row.AvailableAt);
        command.AddNullableDateTimeOffsetParameter("$sentAt", row.SentAt);
        command.AddNullableDateTimeOffsetParameter("$failedAt", row.FailedAt);
        command.AddNullableDateTimeOffsetParameter("$discardedAt", row.DiscardedAt);
        command.AddParameter("$lockedBy", row.LockedUntil == null ? null : "worker");
        command.AddNullableDateTimeOffsetParameter("$lockedUntil", row.LockedUntil);
        command.AddParameter("$body", row.Body);
        command.AddParameter("$attemptCount", row.AttemptCount);
        command.AddParameter("$lastError", row.FailedAt == null ? null : "failure");
        await command.ExecuteNonQueryAsync();
    }

    protected override async Task<int> CountWebhookOutboxRowsAsync()
    {
        await using var connection = new Microsoft.Data.Sqlite.SqliteConnection(_database!.ConnectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT count(*) FROM ashlar_security_event_webhook_outbox;";
        return Convert.ToInt32(await command.ExecuteScalarAsync(), CultureInfo.InvariantCulture);
    }

    protected override async Task<int> CountWebhookOutboxRowsByEndpointNameAsync(string endpointName)
    {
        await using var connection = new Microsoft.Data.Sqlite.SqliteConnection(_database!.ConnectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT count(*) FROM ashlar_security_event_webhook_outbox WHERE endpoint_name = $endpointName;";
        command.AddParameter("$endpointName", endpointName);
        return Convert.ToInt32(await command.ExecuteScalarAsync(), CultureInfo.InvariantCulture);
    }
}
