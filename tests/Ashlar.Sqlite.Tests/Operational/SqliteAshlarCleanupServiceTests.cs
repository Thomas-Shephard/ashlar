using Ashlar.Operational;
using System.Globalization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Sqlite.Tests.Operational;

internal sealed class SqliteAshlarCleanupServiceTests : SqliteTestBase
{
    private static readonly Guid TestUserId = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
    private static readonly DateTimeOffset Now = new(2026, 5, 8, 12, 0, 0, TimeSpan.Zero);
    private static readonly string[] SeedPrefixes = ["s", "c", "g", "i", "h", "p", "e", "o"];
    private FakeTimeProvider _timeProvider = null!;
    private ServiceProvider _provider = null!;

    [SetUp]
    public async Task SetUpAsync()
    {
        _timeProvider = new FakeTimeProvider(Now);
        var services = new ServiceCollection();
        services.AddAshlarSqlite(GetConnectionString());
        services.AddAshlarSqliteCleanup(options =>
        {
            options.BatchSize = 100;
            options.RemoveAuditEventsAfter = TimeSpan.FromDays(90);
        });
        services.AddSingleton<TimeProvider>(_timeProvider);
        _provider = services.BuildServiceProvider();
        await _provider.InitializeAshlarSqliteSchemaAsync();
    }

    [TearDown]
    public async Task TearDownAsync()
    {
        await _provider.DisposeAsync();
    }

    [Test]
    public async Task CleanupAsyncOnEmptyDatabaseReturnsZeroCounts()
    {
        var result = await _provider.GetRequiredService<IAshlarCleanupService>().CleanupAsync();

        Assert.That(result, Is.EqualTo(AshlarCleanupResult.Empty));
    }

    [Test]
    public async Task CleanupAsyncRemovesOnlyRowsPastRetentionThresholds()
    {
        await SeedMixedRowsAsync();

        var result = await _provider.GetRequiredService<IAshlarCleanupService>().CleanupAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.ExpiredSessions, Is.EqualTo(1));
            Assert.That(result.RevokedSessions, Is.EqualTo(1));
            Assert.That(result.ExpiredCredentials, Is.EqualTo(1));
            Assert.That(result.RevokedCredentials, Is.EqualTo(1));
            Assert.That(result.ExpiredAuthorizationGrants, Is.EqualTo(1));
            Assert.That(result.RevokedAuthorizationGrants, Is.EqualTo(1));
            Assert.That(result.ExpiredInvitations, Is.EqualTo(1));
            Assert.That(result.AcceptedInvitations, Is.EqualTo(1));
            Assert.That(result.RevokedInvitations, Is.EqualTo(1));
            Assert.That(result.ExpiredHandshakes, Is.EqualTo(1));
            Assert.That(result.CompletedHandshakes, Is.EqualTo(1));
            Assert.That(result.RevokedHandshakes, Is.EqualTo(1));
            Assert.That(result.ExpiredRateLimits, Is.EqualTo(1));
            Assert.That(result.ExpiredPasskeyChallenges, Is.EqualTo(1));
            Assert.That(result.ConsumedPasskeyChallenges, Is.EqualTo(1));
            Assert.That(result.AuditEvents, Is.EqualTo(1));
            Assert.That(result.SentEmails, Is.EqualTo(1));
            Assert.That(result.FailedEmails, Is.EqualTo(1));
        }

        using (Assert.EnterMultipleScope())
        {
            Assert.That(await CountAsync("ashlar_sessions"), Is.EqualTo(2));
            Assert.That(await CountAsync("ashlar_credentials"), Is.EqualTo(2));
            Assert.That(await CountAsync("ashlar_authorization_grants"), Is.EqualTo(2));
            Assert.That(await CountAsync("ashlar_invitations"), Is.EqualTo(3));
            Assert.That(await CountAsync("ashlar_mfa_handshakes"), Is.EqualTo(3));
            Assert.That(await CountAsync("ashlar_rate_limits"), Is.EqualTo(1));
            Assert.That(await CountAsync("ashlar_passkey_challenges"), Is.EqualTo(2));
            Assert.That(await CountAsync("ashlar_security_events"), Is.EqualTo(1));
            Assert.That(await CountAsync("ashlar_email_outbox"), Is.EqualTo(2));
        }
    }

    [Test]
    public async Task CleanupAsyncRespectsBatchLimitsAndRepeatedCleanupIsIdempotent()
    {
        await SeedUserAsync();
        for (var index = 0; index < 3; index++)
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

        var service = new SqliteAshlarCleanupService(
            _provider.GetRequiredService<ISqliteConnectionProvider>(),
            _timeProvider,
            Options.Create(new AshlarCleanupOptions { BatchSize = 2, MaxBatchesPerRun = 1, RemoveAuditEventsAfter = TimeSpan.FromDays(1) }));

        var first = await service.CleanupAsync();
        var second = await service.CleanupAsync();
        var third = await service.CleanupAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(first.ExpiredSessions, Is.EqualTo(2));
            Assert.That(second.ExpiredSessions, Is.EqualTo(1));
            Assert.That(third.Total, Is.Zero);
        }
    }

    [Test]
    public async Task CleanupAsyncRemovesSensitiveSentRowsUsingSensitiveRetention()
    {
        await ExecuteAsync("""
            INSERT INTO ashlar_email_outbox (id, to_address, subject, text_body, sensitivity, body_protection, created_at, available_at, sent_at) VALUES
            ($sensitiveOld, 'old-secret@example.com', 'sensitive-old-sent', 'live-token-link', 'ContainsLiveSecret', 'SecretProtector', $old, $old, $old),
            ($sensitiveRecent, 'recent-secret@example.com', 'sensitive-recent-sent', 'live-token-link', 'ContainsLiveSecret', 'SecretProtector', $recent, $recent, $recent),
            ($normalOld, 'normal@example.com', 'normal-old-sent', 'normal-body', 'Normal', 'None', $old, $old, $old);
            """, command =>
        {
            command.AddGuidParameter("$sensitiveOld", Guid.NewGuid());
            command.AddGuidParameter("$sensitiveRecent", Guid.NewGuid());
            command.AddGuidParameter("$normalOld", Guid.NewGuid());
            command.AddDateTimeOffsetParameter("$old", Now.AddHours(-2));
            command.AddDateTimeOffsetParameter("$recent", Now.AddMinutes(-30));
        });

        var result = await _provider.GetRequiredService<IAshlarCleanupService>().CleanupAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.SentSensitiveEmails, Is.EqualTo(1));
            Assert.That(result.SentEmails, Is.Zero);
            Assert.That(await CountEmailSubjectAsync("sensitive-old-sent"), Is.Zero);
            Assert.That(await CountEmailSubjectAsync("sensitive-recent-sent"), Is.EqualTo(1));
            Assert.That(await CountEmailSubjectAsync("normal-old-sent"), Is.EqualTo(1));
        }
    }

    [Test]
    public async Task CleanupAsyncRemovesSensitiveTerminalFailedRowsUsingSensitiveRetention()
    {
        await ExecuteAsync("""
            INSERT INTO ashlar_email_outbox (id, to_address, subject, text_body, sensitivity, body_protection, created_at, available_at, failed_at) VALUES
            ($sensitiveOld, 'old-secret@example.com', 'sensitive-old-failed', 'live-token-link', 'ContainsLiveSecret', 'SecretProtector', $old, $old, $old),
            ($sensitiveRecent, 'recent-secret@example.com', 'sensitive-recent-failed', 'live-token-link', 'ContainsLiveSecret', 'SecretProtector', $recent, $recent, $recent),
            ($normalOld, 'normal@example.com', 'normal-old-failed', 'normal-body', 'Normal', 'None', $old, $old, $old);
            """, command =>
        {
            command.AddGuidParameter("$sensitiveOld", Guid.NewGuid());
            command.AddGuidParameter("$sensitiveRecent", Guid.NewGuid());
            command.AddGuidParameter("$normalOld", Guid.NewGuid());
            command.AddDateTimeOffsetParameter("$old", Now.AddHours(-2));
            command.AddDateTimeOffsetParameter("$recent", Now.AddMinutes(-30));
        });

        var result = await _provider.GetRequiredService<IAshlarCleanupService>().CleanupAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailedSensitiveEmails, Is.EqualTo(1));
            Assert.That(result.FailedEmails, Is.Zero);
            Assert.That(await CountEmailSubjectAsync("sensitive-old-failed"), Is.Zero);
            Assert.That(await CountEmailSubjectAsync("sensitive-recent-failed"), Is.EqualTo(1));
            Assert.That(await CountEmailSubjectAsync("normal-old-failed"), Is.EqualTo(1));
        }
    }

    [Test]
    public async Task CleanupAsyncDoesNotRemovePendingOrLockedSensitiveRows()
    {
        await ExecuteAsync("""
            INSERT INTO ashlar_email_outbox (id, to_address, subject, text_body, sensitivity, body_protection, created_at, available_at) VALUES
            ($pending, 'pending-secret@example.com', 'sensitive-pending', 'live-token-link', 'ContainsLiveSecret', 'SecretProtector', $old, $old);

            INSERT INTO ashlar_email_outbox (id, to_address, subject, text_body, sensitivity, body_protection, created_at, available_at, locked_until, locked_by) VALUES
            ($locked, 'locked-secret@example.com', 'sensitive-locked', 'live-token-link', 'ContainsLiveSecret', 'SecretProtector', $old, $old, $lockedUntil, 'worker');
            """, command =>
        {
            command.AddGuidParameter("$pending", Guid.NewGuid());
            command.AddGuidParameter("$locked", Guid.NewGuid());
            command.AddDateTimeOffsetParameter("$old", Now.AddDays(-30));
            command.AddDateTimeOffsetParameter("$lockedUntil", Now.AddMinutes(5));
        });

        var result = await _provider.GetRequiredService<IAshlarCleanupService>().CleanupAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.SentSensitiveEmails, Is.Zero);
            Assert.That(result.FailedSensitiveEmails, Is.Zero);
            Assert.That(await CountEmailSubjectAsync("sensitive-pending"), Is.EqualTo(1));
            Assert.That(await CountEmailSubjectAsync("sensitive-locked"), Is.EqualTo(1));
        }
    }

    [Test]
    public async Task CleanupAsyncSkipsCategoriesWithNullRetention()
    {
        await ExecuteAsync(
            "INSERT INTO ashlar_security_events (id, event_type, occurred_at) VALUES ($id, 'old-event', $occurred);",
            command =>
            {
                command.AddGuidParameter("$id", Guid.NewGuid());
                command.AddDateTimeOffsetParameter("$occurred", Now.AddYears(-10));
            });

        var service = new SqliteAshlarCleanupService(
            _provider.GetRequiredService<ISqliteConnectionProvider>(),
            _timeProvider,
            Options.Create(new AshlarCleanupOptions()));

        var result = await service.CleanupAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.AuditEvents, Is.Zero);
            Assert.That(await CountAsync("ashlar_security_events"), Is.EqualTo(1));
        }
    }

    [Test]
    public void ConstructorRejectsInvalidOptionsWhenValidationIsBypassed()
    {
        Assert.Throws<ArgumentException>(() => _ = new SqliteAshlarCleanupService(
            _provider.GetRequiredService<ISqliteConnectionProvider>(),
            _timeProvider,
            Options.Create(new AshlarCleanupOptions { BatchSize = 0 })));
    }

    [Test]
    public async Task CleanupAsyncLogsCategoryContextWhenDeleteFails()
    {
        await ExecuteAsync("DROP TABLE ashlar_sessions;", _ => { });
        var logger = new TestLogger<SqliteAshlarCleanupService>();
        var service = new SqliteAshlarCleanupService(
            _provider.GetRequiredService<ISqliteConnectionProvider>(),
            _timeProvider,
            Options.Create(new AshlarCleanupOptions()),
            logger);

        Assert.ThrowsAsync<Microsoft.Data.Sqlite.SqliteException>(async () => await service.CleanupAsync());

        Assert.That(logger.Messages, Has.Some.Matches<string>(message =>
            message.Contains("SQLite cleanup category failed", StringComparison.Ordinal)
            && message.Contains("Category=expired_sessions", StringComparison.Ordinal)
            && message.Contains("TableName=ashlar_sessions", StringComparison.Ordinal)));
    }

    [Test]
    public async Task CleanupAsyncParticipatesInAshlarTransactionRollback()
    {
        await SeedUserAsync();
        await ExecuteAsync(
            "INSERT INTO ashlar_rate_limits (purpose, rate_limit_key, count, window_start, expires_at) VALUES ('login', 'rollback', 1, $old, $old);",
            command => command.AddDateTimeOffsetParameter("$old", Now.AddDays(-10)));

        var transactionProvider = _provider.GetRequiredService<Ashlar.Identity.Abstractions.Transactions.AshlarDurableTransactionProvider>();
        var cleanup = _provider.GetRequiredService<IAshlarCleanupService>();

        await using (var transaction = await transactionProvider.BeginTransactionAsync())
        {
            var result = await cleanup.CleanupAsync();
            Assert.That(result.ExpiredRateLimits, Is.EqualTo(1));
            await transaction.RollbackAsync();
        }

        Assert.That(await CountAsync("ashlar_rate_limits"), Is.EqualTo(1));
    }

    private async Task SeedMixedRowsAsync()
    {
        await SeedUserAsync();
        var old = Now.AddDays(-60);
        var oldCreated = Now.AddDays(-61);
        var veryOld = Now.AddDays(-120);
        var recent = Now.AddHours(-1);
        var future = Now.AddDays(1);

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

            INSERT INTO ashlar_invitations (id, display_email, normalized_email, token_hash, created_at, expires_at, accepted_at, revoked_at, version) VALUES
            ($i1, 'a@example.com', 'A@EXAMPLE.COM', 'expired-invite', $old, $old, NULL, NULL, 'v1'),
            ($i2, 'b@example.com', 'B@EXAMPLE.COM', 'accepted-invite', $old, $future, $old, NULL, 'v1'),
            ($i3, 'c@example.com', 'C@EXAMPLE.COM', 'revoked-invite', $old, $future, NULL, $old, 'v1'),
            ($i4, 'd@example.com', 'D@EXAMPLE.COM', 'pending-invite', $now, $future, NULL, NULL, 'v1'),
            ($i5, 'e@example.com', 'E@EXAMPLE.COM', 'recent-accepted-invite', $now, $future, $recent, NULL, 'v1'),
            ($i6, 'f@example.com', 'F@EXAMPLE.COM', 'recent-revoked-invite', $now, $future, NULL, $recent, 'v1');

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

            INSERT INTO ashlar_email_outbox (id, to_address, subject, created_at, available_at, sent_at, failed_at) VALUES
            ($o1, 'a@example.com', 'sent', $old, $old, $old, NULL),
            ($o2, 'b@example.com', 'failed', $old, $old, NULL, $old),
            ($o3, 'c@example.com', 'pending', $now, $now, NULL, NULL),
            ($o4, 'd@example.com', 'recent-sent', $now, $now, $recent, NULL);
            """, command =>
        {
            command.AddGuidParameter("$userId", TestUserId);
            command.AddDateTimeOffsetParameter("$now", Now);
            command.AddDateTimeOffsetParameter("$recent", recent);
            command.AddDateTimeOffsetParameter("$old", old);
            command.AddDateTimeOffsetParameter("$oldCreated", oldCreated);
            command.AddDateTimeOffsetParameter("$veryOld", veryOld);
            command.AddDateTimeOffsetParameter("$future", future);
            foreach (var prefix in SeedPrefixes)
            {
                var count = prefix is "s" or "c" or "g" or "p" or "o" ? 4 : prefix == "e" ? 2 : 6;
                for (var index = 1; index <= count; index++)
                {
                    command.AddGuidParameter($"${prefix}{index}", Guid.NewGuid());
                }
            }
        });
    }

    private async Task SeedUserAsync()
    {
        await ExecuteAsync(
            "INSERT INTO ashlar_users (id, display_email, normalized_email, created_at) VALUES ($id, 'test@example.com', 'TEST@EXAMPLE.COM', $now);",
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

    private async Task<int> CountAsync(string table)
    {
        await using var connection = await OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = $"SELECT count(*) FROM {table};";
        return Convert.ToInt32(await command.ExecuteScalarAsync(), CultureInfo.InvariantCulture);
    }

    private async Task<int> CountEmailSubjectAsync(string subject)
    {
        await using var connection = await OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT count(*) FROM ashlar_email_outbox WHERE subject = $subject;";
        command.AddParameter("$subject", subject);
        return Convert.ToInt32(await command.ExecuteScalarAsync(), CultureInfo.InvariantCulture);
    }

    private sealed class TestLogger<T> : ILogger<T>
    {
        public List<string> Messages { get; } = [];

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            Messages.Add(formatter(state, exception));
        }
    }
}
