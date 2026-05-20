using Ashlar.Operational;
using Dapper;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Npgsql;

namespace Ashlar.Postgres.Tests.Operational;

internal sealed class PostgresAshlarCleanupServiceContractTests : AshlarCleanupServiceContractTests
{
    private static readonly Guid TestUserId = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
    private static readonly DateTimeOffset Now = new(2026, 5, 8, 12, 0, 0, TimeSpan.Zero);
    private PostgresContractDatabaseLease? _database;
    private FakeTimeProvider _timeProvider = null!;

    protected override async Task<IServiceProvider> CreateInitializedServiceProviderAsync()
    {
        _timeProvider = new FakeTimeProvider(Now);
        _database = await PostgresContractDatabase.CreateInitializedServiceProviderAsync(services =>
        {
            services.AddAshlarPostgresCleanup(options =>
            {
                options.BatchSize = 2;
                options.MaxBatchesPerRun = 1;
                options.RemoveAuditEventsAfter = TimeSpan.FromDays(90);
            });
            services.AddSingleton<TimeProvider>(_timeProvider);
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

    protected override async Task SeedMixedCleanupRowsAsync()
    {
        await SeedUserAsync();
        await using var connection = await OpenConnectionAsync();
        await connection.ExecuteAsync("""
            INSERT INTO ashlar_sessions (id, user_id, token_hash, created_at, expires_at, revoked_at) VALUES
            (@s1, @userId, 'expired-session', @old, @old, NULL),
            (@s2, @userId, 'revoked-session', @old, @future, @old),
            (@s3, @userId, 'active-session', @now, @future, NULL),
            (@s4, @userId, 'recent-revoked-session', @now, @future, @recent);

            INSERT INTO ashlar_credentials (id, user_id, provider_type, provider_name, provider_key, version, created_at, expires_at, revoked_at, status) VALUES
            (@c1, @userId, 'local', 'password', 'expired', 'v1', @old, @old, NULL, 0),
            (@c2, @userId, 'local', 'password', 'revoked', 'v1', @old, NULL, @old, 1),
            (@c3, @userId, 'local', 'password', 'active', 'v1', @now, @future, NULL, 0),
            (@c4, @userId, 'local', 'password', 'recent-revoked', 'v1', @now, NULL, @recent, 1);

            INSERT INTO ashlar_authorization_grants (id, user_id, permission, created_at, expires_at, revoked_at) VALUES
            (@g1, @userId, 'expired', @old, @old, NULL),
            (@g2, @userId, 'revoked', @old, NULL, @old),
            (@g3, @userId, 'active', @now, @future, NULL),
            (@g4, @userId, 'recent-revoked', @now, NULL, @recent);

            INSERT INTO ashlar_invitations (id, email, normalized_email, token_hash, created_at, expires_at, accepted_at, revoked_at, version) VALUES
            (@i1, 'a@example.com', 'a@example.com', 'expired-invite', @old, @old, NULL, NULL, 'v1'),
            (@i2, 'b@example.com', 'b@example.com', 'accepted-invite', @old, @future, @old, NULL, 'v1'),
            (@i3, 'c@example.com', 'c@example.com', 'revoked-invite', @old, @future, NULL, @old, 'v1'),
            (@i4, 'd@example.com', 'd@example.com', 'pending-invite', @now, @future, NULL, NULL, 'v1'),
            (@i5, 'e@example.com', 'e@example.com', 'recent-accepted-invite', @now, @future, @recent, NULL, 'v1'),
            (@i6, 'f@example.com', 'f@example.com', 'recent-revoked-invite', @now, @future, NULL, @recent, 'v1');

            INSERT INTO ashlar_mfa_handshakes (id, user_id, token_hash, created_at, expires_at, is_revoked, is_completed, revoked_at, completed_at, required_factors, verified_factors) VALUES
            (@h1, @userId, 'expired-handshake', @old, @old, false, false, NULL, NULL, '[]'::jsonb, '[]'::jsonb),
            (@h2, @userId, 'completed-handshake', @old, @future, false, true, NULL, @old, '[]'::jsonb, '[]'::jsonb),
            (@h3, @userId, 'revoked-handshake', @old, @future, true, false, @old, NULL, '[]'::jsonb, '[]'::jsonb),
            (@h4, @userId, 'pending-handshake', @now, @future, false, false, NULL, NULL, '[]'::jsonb, '[]'::jsonb),
            (@h5, @userId, 'recent-completed-handshake', @now, @future, false, true, NULL, @recent, '[]'::jsonb, '[]'::jsonb),
            (@h6, @userId, 'recent-revoked-handshake', @now, @future, true, false, @recent, NULL, '[]'::jsonb, '[]'::jsonb);

            INSERT INTO ashlar_rate_limits (purpose, rate_limit_key, count, window_start, expires_at) VALUES
            ('login', 'expired-rate', 1, @old, @old),
            ('login', 'active-rate', 1, @now, @future);

            INSERT INTO ashlar_passkey_challenges (id, version, purpose, user_id, challenge, options_json, relying_party_id, origin, created_at, expires_at, consumed_at) VALUES
            (@p1, 'v1', 'passkey-authentication', NULL, 'expired-passkey-challenge', '{}'::jsonb, 'example.com', 'https://example.com', @oldCreated, @old, NULL),
            (@p2, 'v1', 'passkey-authentication', NULL, 'consumed-passkey-challenge', '{}'::jsonb, 'example.com', 'https://example.com', @oldCreated, @future, @old),
            (@p3, 'v1', 'passkey-authentication', NULL, 'active-passkey-challenge', '{}'::jsonb, 'example.com', 'https://example.com', @now, @future, NULL),
            (@p4, 'v1', 'passkey-authentication', NULL, 'recent-consumed-passkey-challenge', '{}'::jsonb, 'example.com', 'https://example.com', @now, @future, @recent);

            INSERT INTO ashlar_security_events (id, event_type, occurred_at) VALUES
            (@e1, 'old-event', @veryOld),
            (@e2, 'recent-event', @recent);
            """, SeedParameters());
    }

    protected override async Task SeedExpiredSessionsAsync(int count)
    {
        await SeedUserAsync();
        await using var connection = await OpenConnectionAsync();
        for (var index = 0; index < count; index++)
        {
            await connection.ExecuteAsync(
                "INSERT INTO ashlar_sessions (id, user_id, token_hash, created_at, expires_at) VALUES (@id, @userId, @token, @created, @expires)",
                new { id = Guid.NewGuid(), userId = TestUserId, token = $"batch-{index}", created = Now.AddDays(-20), expires = Now.AddDays(-10) });
        }
    }

    protected override async Task SeedOldAuditEventAsync()
    {
        await using var connection = await OpenConnectionAsync();
        await connection.ExecuteAsync(
            "INSERT INTO ashlar_security_events (id, event_type, occurred_at) VALUES (@id, 'old-event', @occurred)",
            new { id = Guid.NewGuid(), occurred = Now.AddYears(-10) });
    }

    protected override async Task<int> CountRowsAsync(string tableName)
    {
        await using var connection = await OpenConnectionAsync();
        return await connection.ExecuteScalarAsync<int>($"SELECT count(*) FROM {tableName}");
    }

    protected override async Task<AshlarCleanupResult> RunCleanupWithNullAuditRetentionAsync()
    {
        if (_database == null)
        {
            throw new InvalidOperationException("Contract database is not initialized.");
        }

        await using var dataSource = new NpgsqlDataSourceBuilder(_database.ConnectionString).Build();
        var service = new PostgresAshlarCleanupService(
            dataSource,
            _timeProvider,
            Options.Create(new AshlarCleanupOptions { RemoveAuditEventsAfter = null }));
        return await service.CleanupAsync();
    }

    private async Task<NpgsqlConnection> OpenConnectionAsync()
    {
        if (_database == null)
        {
            throw new InvalidOperationException("Contract database is not initialized.");
        }

        var connection = new NpgsqlConnection(_database.ConnectionString);
        await connection.OpenAsync();
        return connection;
    }

    private async Task SeedUserAsync()
    {
        await using var connection = await OpenConnectionAsync();
        await connection.ExecuteAsync(
            "INSERT INTO ashlar_users (id, email, normalized_email, created_at) VALUES (@id, 'test@example.com', 'test@example.com', @now) ON CONFLICT DO NOTHING",
            new { id = TestUserId, now = Now });
    }

    private static object SeedParameters() => new
    {
        userId = TestUserId,
        now = Now,
        recent = Now.AddHours(-1),
        old = Now.AddDays(-60),
        oldCreated = Now.AddDays(-61),
        veryOld = Now.AddDays(-120),
        future = Now.AddDays(1),
        s1 = Guid.NewGuid(),
        s2 = Guid.NewGuid(),
        s3 = Guid.NewGuid(),
        s4 = Guid.NewGuid(),
        c1 = Guid.NewGuid(),
        c2 = Guid.NewGuid(),
        c3 = Guid.NewGuid(),
        c4 = Guid.NewGuid(),
        g1 = Guid.NewGuid(),
        g2 = Guid.NewGuid(),
        g3 = Guid.NewGuid(),
        g4 = Guid.NewGuid(),
        i1 = Guid.NewGuid(),
        i2 = Guid.NewGuid(),
        i3 = Guid.NewGuid(),
        i4 = Guid.NewGuid(),
        i5 = Guid.NewGuid(),
        i6 = Guid.NewGuid(),
        h1 = Guid.NewGuid(),
        h2 = Guid.NewGuid(),
        h3 = Guid.NewGuid(),
        h4 = Guid.NewGuid(),
        h5 = Guid.NewGuid(),
        h6 = Guid.NewGuid(),
        p1 = Guid.NewGuid(),
        p2 = Guid.NewGuid(),
        p3 = Guid.NewGuid(),
        p4 = Guid.NewGuid(),
        e1 = Guid.NewGuid(),
        e2 = Guid.NewGuid()
    };
}










