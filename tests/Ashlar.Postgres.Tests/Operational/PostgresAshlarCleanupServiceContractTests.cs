using Ashlar.Operational;
using Dapper;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using Npgsql;

namespace Ashlar.Postgres.Tests.Operational;

internal sealed class PostgresAshlarCleanupServiceContractTests : AshlarCleanupServiceContractTests
{
    protected override Task<AshlarCleanupResult> RunCleanupAsync(IServiceProvider serviceProvider) =>
        serviceProvider.GetRequiredService<PostgresAshlarCleanupService>().CleanupAsync();

    private static readonly Guid TestUserId = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
    private static readonly DateTimeOffset Now = new(2026, 5, 8, 12, 0, 0, TimeSpan.Zero);
    private PostgresContractDatabaseLease? _database;
    private FakeTimeProvider _timeProvider = null!;

    protected override bool SupportsCleanupTransactionRollback => true;

    protected override async Task<IServiceProvider> CreateInitializedServiceProviderAsync()
    {
        _timeProvider = new FakeTimeProvider(Now);
        _database = await PostgresContractDatabase.CreateInitializedServiceProviderAsync(services =>
        {
            services.AddAshlarPostgresCleanupInfrastructure(options =>
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

            INSERT INTO ashlar_invitations (id, display_email, normalized_email, token_hash, created_at, expires_at, accepted_at, revoked_at, version) VALUES
            (@i1, 'a@example.com', 'A@EXAMPLE.COM', 'expired-invite', @old, @old, NULL, NULL, 'v1'),
            (@i2, 'b@example.com', 'B@EXAMPLE.COM', 'accepted-invite', @old, @future, @old, NULL, 'v1'),
            (@i3, 'c@example.com', 'C@EXAMPLE.COM', 'revoked-invite', @old, @future, NULL, @old, 'v1'),
            (@i4, 'd@example.com', 'D@EXAMPLE.COM', 'pending-invite', @now, @future, NULL, NULL, 'v1'),
            (@i5, 'e@example.com', 'E@EXAMPLE.COM', 'recent-accepted-invite', @now, @future, @recent, NULL, 'v1'),
            (@i6, 'f@example.com', 'F@EXAMPLE.COM', 'recent-revoked-invite', @now, @future, NULL, @recent, 'v1');

            INSERT INTO ashlar_mfa_handshakes (id, user_id, purpose, token_hash, created_at, expires_at, is_revoked, is_completed, revoked_at, completed_at, required_factors, verified_factors) VALUES
            (@h1, @userId, 1, 'expired-handshake', @old, @old, false, false, NULL, NULL, '[]'::jsonb, '[]'::jsonb),
            (@h2, @userId, 1, 'completed-handshake', @old, @future, false, true, NULL, @old, '[]'::jsonb, '[]'::jsonb),
            (@h3, @userId, 1, 'revoked-handshake', @old, @future, true, false, @old, NULL, '[]'::jsonb, '[]'::jsonb),
            (@h4, @userId, 1, 'pending-handshake', @now, @future, false, false, NULL, NULL, '[]'::jsonb, '[]'::jsonb),
            (@h5, @userId, 1, 'recent-completed-handshake', @now, @future, false, true, NULL, @recent, '[]'::jsonb, '[]'::jsonb),
            (@h6, @userId, 1, 'recent-revoked-handshake', @now, @future, true, false, @recent, NULL, '[]'::jsonb, '[]'::jsonb);

            INSERT INTO ashlar_remembered_mfa_devices (id, user_id, token_selector, token_hash, created_at, expires_at, revoked_at) VALUES
            (@r1, @userId, 'expired-remembered-device', 'hash-1', @old, @old, NULL),
            (@r2, @userId, 'revoked-remembered-device', 'hash-2', @old, @future, @old),
            (@r3, @userId, 'active-remembered-device', 'hash-3', @now, @future, NULL),
            (@r4, @userId, 'recent-revoked-remembered-device', 'hash-4', @now, @future, @recent);

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

    protected override async Task SeedOldRememberedMfaDevicesAsync()
    {
        await SeedUserAsync();
        await using var connection = await OpenConnectionAsync();
        await connection.ExecuteAsync("""
            INSERT INTO ashlar_remembered_mfa_devices (id, user_id, token_selector, token_hash, created_at, expires_at, revoked_at) VALUES
            (@expired, @userId, 'expired-remembered-device-null-retention', 'hash-expired', @old, @old, NULL),
            (@revoked, @userId, 'revoked-remembered-device-null-retention', 'hash-revoked', @old, @future, @old);
            """, new
        {
            expired = Guid.NewGuid(),
            revoked = Guid.NewGuid(),
            userId = TestUserId,
            old = Now.AddDays(-60),
            future = Now.AddDays(1)
        });
    }

    protected override async Task SeedSensitiveEmailCleanupRowsAsync()
    {
        await using var connection = await OpenConnectionAsync();
        await connection.ExecuteAsync("""
            INSERT INTO ashlar_email_outbox (id, to_address, subject, text_body, sensitivity, body_protection, created_at, available_at, sent_at) VALUES
            (@sensitiveOldSent, 'old-sent@example.com', 'sensitive-old-sent', 'live-token-link', 'ContainsLiveSecret', 'SecretProtector', @old, @old, @old),
            (@sensitiveRecentSent, 'recent-sent@example.com', 'sensitive-recent-sent', 'live-token-link', 'ContainsLiveSecret', 'SecretProtector', @recent, @recent, @recent),
            (@normalOldSent, 'normal-sent@example.com', 'normal-old-sent', 'normal-body', 'Normal', 'None', @old, @old, @old);

            INSERT INTO ashlar_email_outbox (id, to_address, subject, text_body, sensitivity, body_protection, created_at, available_at, failed_at) VALUES
            (@sensitiveOldFailed, 'old-failed@example.com', 'sensitive-old-failed', 'live-token-link', 'ContainsLiveSecret', 'SecretProtector', @old, @old, @old),
            (@sensitiveRecentFailed, 'recent-failed@example.com', 'sensitive-recent-failed', 'live-token-link', 'ContainsLiveSecret', 'SecretProtector', @recent, @recent, @recent),
            (@normalOldFailed, 'normal-failed@example.com', 'normal-old-failed', 'normal-body', 'Normal', 'None', @old, @old, @old);

            INSERT INTO ashlar_email_outbox (id, to_address, subject, text_body, sensitivity, body_protection, created_at, available_at, failed_at, discarded_at) VALUES
            (@sensitiveOldDiscarded, 'old-discarded@example.com', 'sensitive-old-discarded', 'live-token-link', 'ContainsLiveSecret', 'SecretProtector', @old, @old, @old, @old),
            (@sensitiveRecentDiscarded, 'recent-discarded@example.com', 'sensitive-recent-discarded', 'live-token-link', 'ContainsLiveSecret', 'SecretProtector', @recent, @recent, @recent, @recent),
            (@normalOldDiscarded, 'normal-discarded@example.com', 'normal-old-discarded', 'normal-body', 'Normal', 'None', @old, @old, @old, @old);

            INSERT INTO ashlar_email_outbox (id, to_address, subject, text_body, sensitivity, body_protection, created_at, available_at) VALUES
            (@pending, 'pending@example.com', 'sensitive-pending', 'live-token-link', 'ContainsLiveSecret', 'SecretProtector', @veryOld, @veryOld);

            INSERT INTO ashlar_email_outbox (id, to_address, subject, text_body, sensitivity, body_protection, created_at, available_at, locked_until, locked_by) VALUES
            (@locked, 'locked@example.com', 'sensitive-locked', 'live-token-link', 'ContainsLiveSecret', 'SecretProtector', @veryOld, @veryOld, @future, 'worker');
            """, new
        {
            sensitiveOldSent = Guid.NewGuid(),
            sensitiveRecentSent = Guid.NewGuid(),
            normalOldSent = Guid.NewGuid(),
            sensitiveOldFailed = Guid.NewGuid(),
            sensitiveRecentFailed = Guid.NewGuid(),
            normalOldFailed = Guid.NewGuid(),
            sensitiveOldDiscarded = Guid.NewGuid(),
            sensitiveRecentDiscarded = Guid.NewGuid(),
            normalOldDiscarded = Guid.NewGuid(),
            pending = Guid.NewGuid(),
            locked = Guid.NewGuid(),
            old = Now.AddHours(-2),
            recent = Now.AddMinutes(-30),
            veryOld = Now.AddDays(-30),
            future = Now.AddMinutes(5)
        });
    }

    protected override async Task<int> CountRowsAsync(string tableName)
    {
        await using var connection = await OpenConnectionAsync();
        return await connection.ExecuteScalarAsync<int>($"SELECT count(*) FROM {tableName}");
    }

    protected override async Task<int> CountEmailRowsBySubjectAsync(string subject)
    {
        await using var connection = await OpenConnectionAsync();
        return await connection.ExecuteScalarAsync<int>(
            "SELECT count(*) FROM ashlar_email_outbox WHERE subject = @subject",
            new { subject });
    }

    protected override async Task<AshlarCleanupResult> RunCleanupWithNullAuditRetentionAsync()
    {
        if (_database == null)
        {
            throw new InvalidOperationException("Contract database is not initialized.");
        }

        await using var provider = CreateCleanupProvider(options => options.RemoveAuditEventsAfter = null);
        return await provider.GetRequiredService<PostgresAshlarCleanupService>().CleanupAsync();
    }

    protected override async Task<AshlarCleanupResult> RunCleanupWithNullRememberedMfaDeviceRetentionsAsync()
    {
        if (_database == null)
        {
            throw new InvalidOperationException("Contract database is not initialized.");
        }

        await using var provider = CreateCleanupProvider(options =>
        {
            options.RemoveExpiredRememberedMfaDevicesAfter = null;
            options.RemoveRevokedRememberedMfaDevicesAfter = null;
        });
        return await provider.GetRequiredService<PostgresAshlarCleanupService>().CleanupAsync();
    }

    protected override async Task<AshlarCleanupResult> RunCleanupWithNullEmailDiscardRetentionAsync()
    {
        if (_database == null)
        {
            throw new InvalidOperationException("Contract database is not initialized.");
        }

        await using var provider = CreateCleanupProvider(options =>
        {
            options.RemoveDiscardedEmailsAfter = null;
            options.RemoveDiscardedSensitiveEmailsAfter = null;
        });
        return await provider.GetRequiredService<PostgresAshlarCleanupService>().CleanupAsync();
    }

    private ServiceProvider CreateCleanupProvider(Action<AshlarCleanupOptions> configure)
    {
        if (_database == null)
        {
            throw new InvalidOperationException("Contract database is not initialized.");
        }

        var services = new ServiceCollection();
        services.AddAshlarPostgres(_database.ConnectionString);
        services.AddAshlarPostgresCleanupInfrastructure(configure);
        services.AddSingleton<TimeProvider>(_timeProvider);
        return services.BuildServiceProvider();
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
            "INSERT INTO ashlar_users (id, display_email, normalized_email, created_at) VALUES (@id, 'test@example.com', 'TEST@EXAMPLE.COM', @now) ON CONFLICT DO NOTHING",
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
        r1 = Guid.NewGuid(),
        r2 = Guid.NewGuid(),
        r3 = Guid.NewGuid(),
        r4 = Guid.NewGuid(),
        p1 = Guid.NewGuid(),
        p2 = Guid.NewGuid(),
        p3 = Guid.NewGuid(),
        p4 = Guid.NewGuid(),
        e1 = Guid.NewGuid(),
        e2 = Guid.NewGuid()
    };
}
