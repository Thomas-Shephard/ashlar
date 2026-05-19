using Ashlar.Operational;
using Ashlar.ProviderContractTests.Operational;
using Ashlar.Sqlite.Tests.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using System.Globalization;

namespace Ashlar.Sqlite.Tests;

internal sealed class SqliteAshlarCleanupServiceContractTests : AshlarCleanupServiceContractTests
{
    private static readonly Guid TestUserId = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
    private static readonly DateTimeOffset Now = new(2026, 5, 8, 12, 0, 0, TimeSpan.Zero);
    private static readonly string[] SeedPrefixes = ["s", "c", "g", "i", "h", "p", "e"];
    private SqliteContractDatabase? _database;
    private FakeTimeProvider _timeProvider = null!;

    protected override bool SupportsCleanupTransactionRollback => true;

    protected override async Task<IServiceProvider> CreateInitializedServiceProviderAsync()
    {
        _timeProvider = new FakeTimeProvider(Now);
        _database = await SqliteContractDatabase.CreateAsync(services =>
        {
            services.Configure<AshlarCleanupOptions>(options =>
            {
                options.BatchSize = 2;
                options.MaxBatchesPerRun = 1;
                options.RemoveAuditEventsAfter = TimeSpan.FromDays(90);
            });
            services.AddSingleton<TimeProvider>(_timeProvider);
        });
        return _database.ServiceProvider;
    }

    protected override Task CleanupInitializedServiceProviderAsync()
    {
        _database?.Delete();
        _database = null;
        return Task.CompletedTask;
    }

    protected override async Task SeedMixedCleanupRowsAsync()
    {
        await SeedUserAsync();
        await ExecuteAsync("""
            INSERT INTO ashlar_sessions (id, user_id, token_hash, created_at, expires_at, revoked_at) VALUES
            ($s1, $userId, 'expired-session', $old, $old, NULL),
            ($s2, $userId, 'revoked-session', $old, $future, $old),
            ($s3, $userId, 'active-session', $now, $future, NULL),
            ($s4, $userId, 'recent-revoked-session', $now, $future, $recent);

            INSERT INTO ashlar_credentials (id, user_id, provider_type, provider_name, provider_key, version, created_at, expires_at, revoked_at, status) VALUES
            ($c1, $userId, 'local', 'password', 'expired', 'v1', $old, $old, NULL, 0),
            ($c2, $userId, 'local', 'password', 'revoked', 'v1', $old, NULL, $old, 1),
            ($c3, $userId, 'local', 'password', 'active', 'v1', $now, $future, NULL, 0),
            ($c4, $userId, 'local', 'password', 'recent-revoked', 'v1', $now, NULL, $recent, 1);

            INSERT INTO ashlar_authorization_grants (id, user_id, permission, created_at, expires_at, revoked_at) VALUES
            ($g1, $userId, 'expired', $old, $old, NULL),
            ($g2, $userId, 'revoked', $old, NULL, $old),
            ($g3, $userId, 'active', $now, $future, NULL),
            ($g4, $userId, 'recent-revoked', $now, NULL, $recent);

            INSERT INTO ashlar_invitations (id, email, normalized_email, token_hash, created_at, expires_at, accepted_at, revoked_at, version) VALUES
            ($i1, 'a@example.com', 'a@example.com', 'expired-invite', $old, $old, NULL, NULL, 'v1'),
            ($i2, 'b@example.com', 'b@example.com', 'accepted-invite', $old, $future, $old, NULL, 'v1'),
            ($i3, 'c@example.com', 'c@example.com', 'revoked-invite', $old, $future, NULL, $old, 'v1'),
            ($i4, 'd@example.com', 'd@example.com', 'pending-invite', $now, $future, NULL, NULL, 'v1'),
            ($i5, 'e@example.com', 'e@example.com', 'recent-accepted-invite', $now, $future, $recent, NULL, 'v1'),
            ($i6, 'f@example.com', 'f@example.com', 'recent-revoked-invite', $now, $future, NULL, $recent, 'v1');

            INSERT INTO ashlar_mfa_handshakes (id, user_id, token_hash, created_at, expires_at, is_revoked, is_completed, revoked_at, completed_at, required_factors, verified_factors) VALUES
            ($h1, $userId, 'expired-handshake', $old, $old, 0, 0, NULL, NULL, '[]', '[]'),
            ($h2, $userId, 'completed-handshake', $old, $future, 0, 1, NULL, $old, '[]', '[]'),
            ($h3, $userId, 'revoked-handshake', $old, $future, 1, 0, $old, NULL, '[]', '[]'),
            ($h4, $userId, 'pending-handshake', $now, $future, 0, 0, NULL, NULL, '[]', '[]'),
            ($h5, $userId, 'recent-completed-handshake', $now, $future, 0, 1, NULL, $recent, '[]', '[]'),
            ($h6, $userId, 'recent-revoked-handshake', $now, $future, 1, 0, $recent, NULL, '[]', '[]');

            INSERT INTO ashlar_rate_limits (purpose, rate_limit_key, count, window_start, expires_at) VALUES
            ('login', 'expired-rate', 1, $old, $old),
            ('login', 'active-rate', 1, $now, $future);

            INSERT INTO ashlar_passkey_challenges (id, version, purpose, user_id, challenge, options_json, relying_party_id, origin, created_at, expires_at, consumed_at) VALUES
            ($p1, 'v1', 'passkey-authentication', NULL, 'expired-passkey-challenge', '{}', 'example.com', 'https://example.com', $oldCreated, $old, NULL),
            ($p2, 'v1', 'passkey-authentication', NULL, 'consumed-passkey-challenge', '{}', 'example.com', 'https://example.com', $oldCreated, $future, $old),
            ($p3, 'v1', 'passkey-authentication', NULL, 'active-passkey-challenge', '{}', 'example.com', 'https://example.com', $now, $future, NULL),
            ($p4, 'v1', 'passkey-authentication', NULL, 'recent-consumed-passkey-challenge', '{}', 'example.com', 'https://example.com', $now, $future, $recent);

            INSERT INTO ashlar_security_events (id, event_type, occurred_at) VALUES
            ($e1, 'old-event', $veryOld),
            ($e2, 'recent-event', $recent);
            """, AddMixedParameters);
    }

    protected override async Task SeedExpiredSessionsAsync(int count)
    {
        await SeedUserAsync();
        for (var index = 0; index < count; index++)
        {
            await ExecuteAsync(
                "INSERT INTO ashlar_sessions (id, user_id, token_hash, created_at, expires_at) VALUES ($id, $userId, $token, $created, $expires);",
                command =>
                {
                    command.AddGuidParameter("$id", Guid.NewGuid());
                    command.AddGuidParameter("$userId", TestUserId);
                    command.AddParameter("$token", $"batch-{index}");
                    command.AddDateTimeOffsetParameter("$created", Now.AddDays(-20));
                    command.AddDateTimeOffsetParameter("$expires", Now.AddDays(-10));
                });
        }
    }

    protected override Task SeedOldAuditEventAsync()
    {
        return ExecuteAsync(
            "INSERT INTO ashlar_security_events (id, event_type, occurred_at) VALUES ($id, 'old-event', $occurred);",
            command =>
            {
                command.AddGuidParameter("$id", Guid.NewGuid());
                command.AddDateTimeOffsetParameter("$occurred", Now.AddYears(-10));
            });
    }

    protected override async Task<int> CountRowsAsync(string tableName)
    {
        await using var connection = await OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = $"SELECT count(*) FROM {tableName};";
        return Convert.ToInt32(await command.ExecuteScalarAsync(), CultureInfo.InvariantCulture);
    }

    protected override async Task<AshlarCleanupResult> RunCleanupWithNullAuditRetentionAsync()
    {
        if (_database == null)
        {
            throw new InvalidOperationException("Contract database is not initialized.");
        }

        var services = new ServiceCollection();
        services.AddAshlarSqlite(_database.ConnectionString);
        services.Configure<AshlarCleanupOptions>(options => options.RemoveAuditEventsAfter = null);
        services.AddSingleton<TimeProvider>(_timeProvider);
        await using var provider = services.BuildServiceProvider();
        return await provider.GetRequiredService<IAshlarCleanupService>().CleanupAsync();
    }

    private async Task<Microsoft.Data.Sqlite.SqliteConnection> OpenConnectionAsync()
    {
        if (_database == null)
        {
            throw new InvalidOperationException("Contract database is not initialized.");
        }

        var connection = new Microsoft.Data.Sqlite.SqliteConnection(_database.ConnectionString);
        await connection.OpenAsync();
        return connection;
    }

    private Task SeedUserAsync()
    {
        return ExecuteAsync(
            "INSERT INTO ashlar_users (id, email, normalized_email, created_at) VALUES ($id, 'test@example.com', 'test@example.com', $now);",
            command =>
            {
                command.AddGuidParameter("$id", TestUserId);
                command.AddDateTimeOffsetParameter("$now", Now);
            });
    }

    private async Task ExecuteAsync(string sql, Action<Microsoft.Data.Sqlite.SqliteCommand> configure)
    {
        await using var connection = await OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        configure(command);
        await command.ExecuteNonQueryAsync();
    }

    private static void AddMixedParameters(Microsoft.Data.Sqlite.SqliteCommand command)
    {
        command.AddGuidParameter("$userId", TestUserId);
        command.AddDateTimeOffsetParameter("$now", Now);
        command.AddDateTimeOffsetParameter("$recent", Now.AddHours(-1));
        command.AddDateTimeOffsetParameter("$old", Now.AddDays(-60));
        command.AddDateTimeOffsetParameter("$oldCreated", Now.AddDays(-61));
        command.AddDateTimeOffsetParameter("$veryOld", Now.AddDays(-120));
        command.AddDateTimeOffsetParameter("$future", Now.AddDays(1));
        foreach (var prefix in SeedPrefixes)
        {
            var count = prefix is "s" or "c" or "g" or "p" ? 4 : prefix == "e" ? 2 : 6;
            for (var index = 1; index <= count; index++)
            {
                command.AddGuidParameter($"${prefix}{index}", Guid.NewGuid());
            }
        }
    }
}
