using System.Diagnostics.CodeAnalysis;
using Ashlar.Operational;
using Ashlar.Testing;
using Dapper;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Npgsql;

namespace Ashlar.Postgres.Tests;

internal sealed class PostgresAshlarCleanupServiceTests : PostgresTestBase
{
    private IServiceProvider _serviceProvider;
    private FakeTimeProvider _timeProvider;
    private readonly DateTimeOffset _now = new(2026, 5, 8, 12, 0, 0, TimeSpan.Zero);

    public override async Task OneTimeSetUp()
    {
        await base.OneTimeSetUp();

        _timeProvider = new FakeTimeProvider(_now);
        var services = new ServiceCollection();
        services.AddAshlarPostgres(GetConnectionString());
        services.AddAshlarPostgresCleanup(options =>
        {
            options.BatchSize = 100;
            options.RemoveAuditEventsAfter = TimeSpan.FromDays(90);
        });
        services.AddSingleton<TimeProvider>(_timeProvider);
        _serviceProvider = services.BuildServiceProvider();

        await _serviceProvider.InitializeAshlarPostgresSchemaAsync();
    }

    [OneTimeTearDown]
    public async Task TearDownAsync()
    {
        if (_serviceProvider is IAsyncDisposable asyncDisposable)
        {
            await asyncDisposable.DisposeAsync();
        }
    }

    [SetUp]
    public async Task SetUpAsync()
    {
        await using var connection = await GetDataSource().OpenConnectionAsync();
        await connection.ExecuteAsync("""
            TRUNCATE ashlar_security_events, ashlar_rate_limits, ashlar_mfa_handshakes, ashlar_invitations, ashlar_sessions, ashlar_credentials, ashlar_authorization_grants, ashlar_users CASCADE;
            """);
    }

    [Test]
    public async Task CleanupAsyncOnEmptyDatabaseReturnsZeroCounts()
    {
        using var cleanup = CreateCleanupService();
        var result = await cleanup.Service.CleanupAsync();

        Assert.That(result, Is.EqualTo(AshlarCleanupResult.Empty));
    }

    [Test]
    public async Task CleanupAsyncRemovesOnlyConfiguredExpiredOrRetainedRows()
    {
        await SeedMixedRowsAsync();

        using var cleanup = CreateCleanupService();
        var result = await cleanup.Service.CleanupAsync();

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
            Assert.That(result.AuditEvents, Is.EqualTo(1));
        }

        await using var connection = await GetDataSource().OpenConnectionAsync();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(await CountAsync(connection, "ashlar_sessions"), Is.EqualTo(2));
            Assert.That(await CountAsync(connection, "ashlar_credentials"), Is.EqualTo(2));
            Assert.That(await CountAsync(connection, "ashlar_authorization_grants"), Is.EqualTo(2));
            Assert.That(await CountAsync(connection, "ashlar_invitations"), Is.EqualTo(3));
            Assert.That(await CountAsync(connection, "ashlar_mfa_handshakes"), Is.EqualTo(3));
            Assert.That(await CountAsync(connection, "ashlar_rate_limits"), Is.EqualTo(1));
            Assert.That(await CountAsync(connection, "ashlar_security_events"), Is.EqualTo(1));
        }
    }

    [Test]
    public async Task CleanupAsyncRespectsBatchSizeAndCanBeRepeated()
    {
        await SeedUserAsync();
        await using var connection = await GetDataSource().OpenConnectionAsync();
        for (var index = 0; index < 3; index++)
        {
            await connection.ExecuteAsync(
                "INSERT INTO ashlar_sessions (id, user_id, token_hash, created_at, expires_at) VALUES (@id, @userId, @token, @created, @expires)",
                new { id = Guid.NewGuid(), userId = TestUserId, token = $"batch-{index}", created = _now.AddDays(-20), expires = _now.AddDays(-10) });
        }

        var service = new PostgresAshlarCleanupService(
            GetDataSource(),
            _timeProvider,
            Options.Create(new AshlarCleanupOptions { BatchSize = 2, MaxBatchesPerRun = 1, RemoveAuditEventsAfter = TimeSpan.FromDays(1) }));

        var first = await service.CleanupAsync();
        var second = await service.CleanupAsync();
        var third = await service.CleanupAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(first.ExpiredSessions, Is.EqualTo(2));
            Assert.That(second.ExpiredSessions, Is.EqualTo(1));
            Assert.That(third.ExpiredSessions, Is.Zero);
        }
    }

    [Test]
    public async Task CleanupAsyncProcessesMultipleBatchesUpToRunLimit()
    {
        await SeedUserAsync();
        await using var connection = await GetDataSource().OpenConnectionAsync();
        for (var index = 0; index < 5; index++)
        {
            await connection.ExecuteAsync(
                "INSERT INTO ashlar_sessions (id, user_id, token_hash, created_at, expires_at) VALUES (@id, @userId, @token, @created, @expires)",
                new { id = Guid.NewGuid(), userId = TestUserId, token = $"multi-batch-{index}", created = _now.AddDays(-20), expires = _now.AddDays(-10) });
        }

        var service = new PostgresAshlarCleanupService(
            GetDataSource(),
            _timeProvider,
            Options.Create(new AshlarCleanupOptions { BatchSize = 2, MaxBatchesPerRun = 2, RemoveAuditEventsAfter = TimeSpan.FromDays(1) }));

        var result = await service.CleanupAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.ExpiredSessions, Is.EqualTo(4));
            Assert.That(await CountAsync(connection, "ashlar_sessions"), Is.EqualTo(1));
        }
    }

    [Test]
    public async Task CleanupAsyncIsSafeUnderConcurrentCalls()
    {
        await SeedUserAsync();
        await using (var connection = await GetDataSource().OpenConnectionAsync())
        {
            for (var index = 0; index < 20; index++)
            {
                await connection.ExecuteAsync(
                    "INSERT INTO ashlar_rate_limits (purpose, rate_limit_key, count, window_start, expires_at) VALUES ('login', @key, 1, @start, @expires)",
                    new { key = $"concurrent-{index}", start = _now.AddDays(-3), expires = _now.AddDays(-2) });
            }
        }

        var cleanups = Enumerable.Range(0, 4).Select(_ => CreateCleanupService()).ToArray();
        try
        {
            var results = await Task.WhenAll(cleanups.Select(cleanup => cleanup.Service.CleanupAsync()));

            using (Assert.EnterMultipleScope())
            {
                Assert.That(results.Sum(result => result.ExpiredRateLimits), Is.EqualTo(20));
                await using var connection = await GetDataSource().OpenConnectionAsync();
                Assert.That(await CountAsync(connection, "ashlar_rate_limits"), Is.Zero);
            }
        }
        finally
        {
            foreach (var cleanup in cleanups)
            {
                cleanup.Dispose();
            }
        }
    }

    [Test]
    public void ConstructorRejectsInvalidOptionsWhenValidationIsBypassed()
    {
        Assert.Throws<ArgumentException>(() => _ = new PostgresAshlarCleanupService(
            GetDataSource(),
            _timeProvider,
            Options.Create(new AshlarCleanupOptions { BatchSize = 0 })));
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void ConstructorRejectsNullArguments()
    {
        var options = Options.Create(new AshlarCleanupOptions());

        Assert.Throws<ArgumentNullException>(() => _ = new PostgresAshlarCleanupService(null!, _timeProvider, options));
        Assert.Throws<ArgumentNullException>(() => _ = new PostgresAshlarCleanupService(GetDataSource(), null!, options));
        Assert.Throws<ArgumentNullException>(() => _ = new PostgresAshlarCleanupService(GetDataSource(), _timeProvider, null!));
    }

    [Test]
    public async Task CleanupAsyncSkipsCategoriesWithNullRetention()
    {
        await using var connection = await GetDataSource().OpenConnectionAsync();
        await connection.ExecuteAsync(
            "INSERT INTO ashlar_security_events (id, event_type, occurred_at) VALUES (@id, 'old-event', @occurred)",
            new { id = Guid.NewGuid(), occurred = _now.AddYears(-10) });
        var service = new PostgresAshlarCleanupService(
            GetDataSource(),
            _timeProvider,
            Options.Create(new AshlarCleanupOptions()));

        var result = await service.CleanupAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.AuditEvents, Is.Zero);
            Assert.That(await CountAsync(connection, "ashlar_security_events"), Is.EqualTo(1));
        }
    }

    [Test]
    public async Task CleanupAsyncLogsCategoryWhenDeleteFails()
    {
        var connectionStringBuilder = new NpgsqlConnectionStringBuilder(GetConnectionString())
        {
            SearchPath = "missing_schema"
        };
        await using var dataSource = new NpgsqlDataSourceBuilder(connectionStringBuilder.ConnectionString).Build();
        var logger = new RecordingLogger<PostgresAshlarCleanupService>();
        var service = new PostgresAshlarCleanupService(
            dataSource,
            _timeProvider,
            Options.Create(new AshlarCleanupOptions()),
            logger);

        Assert.ThrowsAsync<PostgresException>(async () => await service.CleanupAsync());

        Assert.That(logger.Entries, Has.Some.Matches<LogEntry>(entry =>
            entry.Level == LogLevel.Error
            && entry.Exception is PostgresException
            && entry.Message.Contains("PostgreSQL cleanup category failed", StringComparison.Ordinal)
            && entry.Message.Contains("Category=expired_sessions", StringComparison.Ordinal)
            && entry.Message.Contains("TableName=ashlar_sessions", StringComparison.Ordinal)));
    }

    private CleanupServiceScope CreateCleanupService()
    {
        var scope = _serviceProvider.CreateScope();
        return new CleanupServiceScope(scope, scope.ServiceProvider.GetRequiredService<IAshlarCleanupService>());
    }

    private sealed record CleanupServiceScope(IServiceScope Scope, IAshlarCleanupService Service) : IDisposable
    {
        public void Dispose()
        {
            Scope.Dispose();
        }
    }

    private static readonly Guid TestUserId = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");

    private async Task SeedMixedRowsAsync()
    {
        await SeedUserAsync();
        await using var connection = await GetDataSource().OpenConnectionAsync();
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

            INSERT INTO ashlar_security_events (id, event_type, occurred_at) VALUES
            (@e1, 'old-event', @veryOld),
            (@e2, 'recent-event', @recent);
            """, new
        {
            userId = TestUserId,
            now = _now,
            recent = _now.AddHours(-1),
            old = _now.AddDays(-60),
            veryOld = _now.AddDays(-120),
            past = _now.AddMinutes(-1),
            future = _now.AddDays(1),
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
            e1 = Guid.NewGuid(),
            e2 = Guid.NewGuid()
        });
    }

    private async Task SeedUserAsync()
    {
        await using var connection = await GetDataSource().OpenConnectionAsync();
        await connection.ExecuteAsync(
            "INSERT INTO ashlar_users (id, email, normalized_email, created_at) VALUES (@id, 'test@example.com', 'test@example.com', @now) ON CONFLICT DO NOTHING",
            new { id = TestUserId, now = _now });
    }

    private static Task<int> CountAsync(System.Data.IDbConnection connection, string tableName)
    {
        return connection.ExecuteScalarAsync<int>($"SELECT count(*) FROM {tableName}");
    }
}
