using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using Dapper;
using Npgsql;

namespace Ashlar.Postgres.Tests.Messaging;

internal sealed class PostgresEmailOutboxContractTests : EmailOutboxContractTests
{
    private PostgresContractDatabaseLease? _database;
    private FakeTimeProvider _timeProvider = null!;

    protected override async Task<IServiceProvider> CreateInitializedServiceProviderAsync()
    {
        _timeProvider = new FakeTimeProvider(ContractNow);
        _database = await PostgresContractDatabase.CreateInitializedServiceProviderAsync(services =>
        {
            services.AddSingleton<TimeProvider>(_timeProvider);
            services.AddSingleton<RecordingEmailTransport>();
            services.AddSingleton<RecordingSecretProtector>();
            services.AddSingleton<Ashlar.Security.Encryption.ISecretProtector>(provider => provider.GetRequiredService<RecordingSecretProtector>());
            services.AddAshlarPostgresEmailOutboxDispatcher<RecordingEmailTransport>(options =>
            {
                options.BatchSize = 2;
                options.InitialRetryDelay = TimeSpan.FromMinutes(1);
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

    protected override Task AdvanceEmailOutboxTimeAsync(TimeSpan offset)
    {
        _timeProvider.Advance(offset);
        return Task.CompletedTask;
    }

    protected override async Task<EmailOutboxRowState> ReadSingleEmailOutboxRowAsync()
    {
        await using var connection = new NpgsqlConnection(_database!.ConnectionString);
        await connection.OpenAsync();
        return await connection.QuerySingleAsync<EmailOutboxRowState>("""
            SELECT text_body AS TextBody,
                   html_body AS HtmlBody,
                   sensitivity AS Sensitivity,
                   body_protection AS BodyProtection,
                   attempt_count AS AttemptCount,
                   last_error AS LastError
            FROM ashlar_email_outbox
            ORDER BY created_at, id
            LIMIT 1;
            """);
    }

    protected override async Task SeedEmailOutboxRowAsync(SeedEmailOutboxRow row)
    {
        await using var connection = new NpgsqlConnection(_database!.ConnectionString);
        await connection.OpenAsync();
        await connection.ExecuteAsync(
            """
            INSERT INTO ashlar_email_outbox (
                id, to_address, subject, text_body, html_body, sensitivity, body_protection,
                created_at, available_at, failed_at, locked_by, locked_until, attempt_count, last_error
            ) VALUES (
                @Id, @ToAddress, @Subject, @TextBody, @HtmlBody, @Sensitivity, @BodyProtection,
                @CreatedAt, @AvailableAt, @FailedAt, @LockedBy, @LockedUntil, @AttemptCount, @LastError
            );
            """,
            row);
    }

    protected override async Task SeedUnknownBodyProtectionEmailOutboxRowAsync(SeedEmailOutboxRow row)
    {
        await using var connection = new NpgsqlConnection(_database!.ConnectionString);
        await connection.OpenAsync();
        // Each contract test gets a fresh database, so this schema mutation is isolated to this test case.
        await connection.ExecuteAsync("ALTER TABLE ashlar_email_outbox DROP CONSTRAINT ck_ashlar_email_outbox_body_protection;");
        await SeedEmailOutboxRowAsync(row);
    }
}
