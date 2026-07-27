using Ashlar.Operational;
using Dapper;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Postgres.Tests.Webhooks;

internal sealed class PostgresSecurityEventWebhookOutboxCleanupContractTests : SecurityEventWebhookOutboxCleanupContractTests
{
    private PostgresContractDatabaseLease? _database;

    protected override Task<AshlarCleanupResult> RunCleanupAsync(IServiceProvider serviceProvider) =>
        serviceProvider.GetRequiredService<PostgresAshlarCleanupService>().CleanupAsync();

    protected override async Task<IServiceProvider> CreateInitializedServiceProviderAsync()
    {
        _database = await PostgresContractDatabase.CreateInitializedServiceProviderAsync(services =>
        {
            services.AddSingleton<TimeProvider>(new FakeTimeProvider(CleanupNow));
            services.AddAshlarPostgresSecurityEventWebhookOutbox();
            services.AddAshlarPostgresCleanupInfrastructure(options =>
            {
                options.BatchSize = 2;
                options.MaxBatchesPerRun = 1;
            });
        });
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

    protected override async Task SeedWebhookOutboxCleanupRowAsync(SeedWebhookCleanupRow row)
    {
        await using var connection = new Npgsql.NpgsqlConnection(_database!.ConnectionString);
        await connection.OpenAsync();
        await connection.ExecuteAsync("""
            INSERT INTO ashlar_security_event_webhook_outbox (
                id, endpoint_name, uri, event_id, event_type, outcome, occurred_at, timeout_ms, body, headers,
                created_at, available_at, sent_at, failed_at, discarded_at, locked_by, locked_until, last_attempt_at, attempt_count, last_error)
            VALUES (
                @id, @endpointName, 'https://example.test/security-events', @eventId, 'security.test', 'success', @createdAt, 1000, @body, '{}'::jsonb,
                @createdAt, @availableAt, @sentAt, @failedAt, @discardedAt, @lockedBy, @lockedUntil, @failedAt, @attemptCount, @lastError);
            """, new
        {
            id = Guid.NewGuid(),
            endpointName = row.EndpointName,
            row.EventId,
            createdAt = row.CreatedAt,
            availableAt = row.AvailableAt,
            row.SentAt,
            row.FailedAt,
            row.DiscardedAt,
            lockedBy = row.LockedUntil == null ? null : "worker",
            row.LockedUntil,
            body = row.Body,
            attemptCount = row.AttemptCount,
            lastError = row.FailedAt == null ? null : "failure"
        });
    }

    protected override async Task<int> CountWebhookOutboxRowsAsync()
    {
        await using var connection = new Npgsql.NpgsqlConnection(_database!.ConnectionString);
        await connection.OpenAsync();
        return await connection.ExecuteScalarAsync<int>("SELECT count(*) FROM ashlar_security_event_webhook_outbox;");
    }

    protected override async Task<int> CountWebhookOutboxRowsByEndpointNameAsync(string endpointName)
    {
        await using var connection = new Npgsql.NpgsqlConnection(_database!.ConnectionString);
        await connection.OpenAsync();
        return await connection.ExecuteScalarAsync<int>(
            "SELECT count(*) FROM ashlar_security_event_webhook_outbox WHERE endpoint_name = @endpointName;",
            new { endpointName });
    }

    protected override async Task<AshlarCleanupResult> RunCleanupWithNullWebhookRetentionsAsync()
    {
        var services = new ServiceCollection();
        services.AddAshlarPostgres(_database!.ConnectionString);
        services.AddSingleton<TimeProvider>(new FakeTimeProvider(CleanupNow));
        services.AddAshlarPostgresCleanupInfrastructure(options =>
        {
            options.RemoveSentSecurityEventWebhooksAfter = null;
            options.RemoveFailedSecurityEventWebhooksAfter = null;
            options.RemoveDiscardedSecurityEventWebhooksAfter = null;
        });
        await using var provider = services.BuildServiceProvider();
        return await provider.GetRequiredService<PostgresAshlarCleanupService>().CleanupAsync();
    }
}
