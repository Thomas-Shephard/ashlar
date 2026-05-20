using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Dapper;
using Npgsql;

namespace Ashlar.Postgres.Tests.RateLimiting;

internal sealed class PostgresAuthenticationRateLimiterTests : PostgresTestBase
{
    private IServiceProvider _serviceProvider;
    private FakeTimeProvider _timeProvider;

    public override async Task OneTimeSetUp()
    {
        await base.OneTimeSetUp();

        _timeProvider = new FakeTimeProvider();

        var services = new ServiceCollection();
        services.AddAshlarPostgres(GetConnectionString());
        services.AddAshlarPostgresRateLimiting();
        services.AddSingleton<TimeProvider>(_timeProvider);
        _serviceProvider = services.BuildServiceProvider();

        await _serviceProvider.InitializeAshlarPostgresSchemaAsync();
    }

    [OneTimeTearDown]
    public async Task OneTimeTearDownAsync()
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
        await connection.ExecuteAsync("TRUNCATE ashlar_rate_limits");
    }

    private IAuthenticationRateLimiter GetLimiter() => _serviceProvider.GetRequiredService<IAuthenticationRateLimiter>();

    [Test]
    public async Task CheckAsyncFirstAttemptIsAllowed()
    {
        var limiter = GetLimiter();
        var attempt = new RateLimitAttempt { Key = "first@example.com" };
        var rule = new RateLimitRule { PermitLimit = 5, Window = TimeSpan.FromMinutes(5) };

        var decision = await limiter.CheckAsync(attempt, rule);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(decision.IsAllowed, Is.True);
            Assert.That(decision.Status, Is.EqualTo(RateLimitStatus.Allowed));
            Assert.That(decision.Remaining, Is.EqualTo(4));
            Assert.That(decision.RetryAfter, Is.Null);
            Assert.That(decision.WindowResetAt, Is.EqualTo(_timeProvider.GetUtcNow() + rule.Window));
        }
    }

    [Test]
    public async Task CheckAsyncAttemptsUpToLimitAreAllowed()
    {
        var limiter = GetLimiter();
        var attempt = new RateLimitAttempt { Key = "limit@example.com" };
        var rule = new RateLimitRule { PermitLimit = 3, Window = TimeSpan.FromMinutes(5) };

        var decision1 = await limiter.CheckAsync(attempt, rule);
        Assert.That(decision1.IsAllowed, Is.True);

        var decision2 = await limiter.CheckAsync(attempt, rule);
        Assert.That(decision2.IsAllowed, Is.True);

        var decision3 = await limiter.CheckAsync(attempt, rule);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(decision3.IsAllowed, Is.True);
            Assert.That(decision3.Remaining, Is.Zero);
        }
    }

    [Test]
    public async Task CheckAsyncAttemptOverLimitIsBlocked()
    {
        var limiter = GetLimiter();
        var attempt = new RateLimitAttempt { Key = "blocked@example.com" };
        var rule = new RateLimitRule { PermitLimit = 2, Window = TimeSpan.FromMinutes(5) };

        await limiter.CheckAsync(attempt, rule);
        await limiter.CheckAsync(attempt, rule);

        var decision = await limiter.CheckAsync(attempt, rule);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(decision.IsAllowed, Is.False);
            Assert.That(decision.Status, Is.EqualTo(RateLimitStatus.Blocked));
            Assert.That(decision.Remaining, Is.Zero);
            Assert.That(decision.RetryAfter, Is.EqualTo(_timeProvider.GetUtcNow() + rule.Window));
        }
    }

    [Test]
    public async Task CheckAsyncAttemptsAllowedAgainAfterWindowExpires()
    {
        var limiter = GetLimiter();
        var attempt = new RateLimitAttempt { Key = "expire@example.com" };
        var rule = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(5) };

        await limiter.CheckAsync(attempt, rule);
        var blockedDecision = await limiter.CheckAsync(attempt, rule);
        Assert.That(blockedDecision.IsAllowed, Is.False);

        _timeProvider.Advance(TimeSpan.FromMinutes(5));
        var allowedDecision = await limiter.CheckAsync(attempt, rule);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(allowedDecision.IsAllowed, Is.True);
            Assert.That(allowedDecision.Remaining, Is.Zero);
        }
    }

    [Test]
    public async Task CheckAsyncBlockDurationExtendsBlockingIfConfigured()
    {
        var limiter = GetLimiter();
        var attempt = new RateLimitAttempt { Key = "block-duration@example.com" };
        var rule = new RateLimitRule
        {
            PermitLimit = 1,
            Window = TimeSpan.FromMinutes(5),
            BlockDuration = TimeSpan.FromMinutes(15)
        };

        var start = _timeProvider.GetUtcNow();
        await limiter.CheckAsync(attempt, rule);

        var blockedDecision = await limiter.CheckAsync(attempt, rule);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(blockedDecision.IsAllowed, Is.False);
            Assert.That(blockedDecision.RetryAfter, Is.EqualTo(start + TimeSpan.FromMinutes(15)));
        }

        _timeProvider.Advance(TimeSpan.FromMinutes(6));
        var stillBlockedDecision = await limiter.CheckAsync(attempt, rule);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(stillBlockedDecision.IsAllowed, Is.False);
            Assert.That(stillBlockedDecision.RetryAfter, Is.EqualTo(start + TimeSpan.FromMinutes(15)));
        }

        _timeProvider.Advance(TimeSpan.FromMinutes(10));
        var allowedDecision = await limiter.CheckAsync(attempt, rule);
        Assert.That(allowedDecision.IsAllowed, Is.True);
    }

    [Test]
    public async Task CheckAsyncDifferentKeysAreIsolated()
    {
        var limiter = GetLimiter();
        var attempt1 = new RateLimitAttempt { Key = "user1" };
        var attempt2 = new RateLimitAttempt { Key = "user2", Purpose = "Login" };
        var attempt3 = new RateLimitAttempt { Key = "user2", Purpose = "Reset" };

        var rule = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(5) };

        await limiter.CheckAsync(attempt1, rule);
        await limiter.CheckAsync(attempt2, rule);

        var user1Blocked = await limiter.CheckAsync(attempt1, rule);
        var user2LoginBlocked = await limiter.CheckAsync(attempt2, rule);
        var user2ResetAllowed = await limiter.CheckAsync(attempt3, rule);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(user1Blocked.IsAllowed, Is.False);
            Assert.That(user2LoginBlocked.IsAllowed, Is.False);
            Assert.That(user2ResetAllowed.IsAllowed, Is.True);
        }
    }

    [Test]
    public async Task CheckAsyncIsSafeUnderConcurrentCalls()
    {
        var limiter = GetLimiter();
        var attempt = new RateLimitAttempt { Key = "concurrent" };
        var rule = new RateLimitRule { PermitLimit = 20, Window = TimeSpan.FromMinutes(5) };

        var tasks = Enumerable.Range(0, 50)
            .Select(_ => Task.Run(() => limiter.CheckAsync(attempt, rule)))
            .ToArray();

        var results = await Task.WhenAll(tasks);

        var allowedCount = results.Count(r => r.IsAllowed);
        var blockedCount = results.Count(r => !r.IsAllowed);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(allowedCount, Is.EqualTo(20));
            Assert.That(blockedCount, Is.EqualTo(30));
        }
    }

    [Test]
    public void CheckAsyncThrowsIfPermitLimitIsInvalid()
    {
        var limiter = GetLimiter();
        var attempt = new RateLimitAttempt { Key = "test" };
        var rule = new RateLimitRule { PermitLimit = 0, Window = TimeSpan.FromMinutes(5) };

        var ex = Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await limiter.CheckAsync(attempt, rule));
        Assert.That(ex?.ParamName, Is.EqualTo("rule"));
    }

    [Test]
    public void CheckAsyncThrowsIfWindowIsInvalid()
    {
        var limiter = GetLimiter();
        var attempt = new RateLimitAttempt { Key = "test" };
        var rule = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.Zero };

        var ex = Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await limiter.CheckAsync(attempt, rule));
        Assert.That(ex?.ParamName, Is.EqualTo("rule"));
    }

    [Test]
    public void CheckAsyncThrowsIfBlockDurationIsInvalid()
    {
        var limiter = GetLimiter();
        var attempt = new RateLimitAttempt { Key = "test" };
        var rule = new RateLimitRule
        {
            PermitLimit = 1,
            Window = TimeSpan.FromMinutes(5),
            BlockDuration = TimeSpan.FromSeconds(-1)
        };

        var ex = Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await limiter.CheckAsync(attempt, rule));
        Assert.That(ex?.ParamName, Is.EqualTo("rule"));
    }

    [Test]
    public async Task CheckAsyncShortBlockDurationDoesNotBypassWindow()
    {
        var limiter = GetLimiter();
        var attempt = new RateLimitAttempt { Key = "block-reset" };
        var rule = new RateLimitRule
        {
            PermitLimit = 1,
            Window = TimeSpan.FromMinutes(5),
            BlockDuration = TimeSpan.FromMinutes(1)
        };

        var start = _timeProvider.GetUtcNow();
        await limiter.CheckAsync(attempt, rule); // Allowed
        await limiter.CheckAsync(attempt, rule); // Blocked

        _timeProvider.Advance(TimeSpan.FromMinutes(1.1));
        var decision = await limiter.CheckAsync(attempt, rule);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(decision.IsAllowed, Is.False, "A shorter BlockDuration should not allow bypassing the Window limit.");
            Assert.That(decision.RetryAfter, Is.EqualTo(start + TimeSpan.FromMinutes(5)));
        }
    }

    [Test]
    public async Task CleanupExpiredRowsShouldWork()
    {
        var limiter = (PostgresAuthenticationRateLimiter)GetLimiter();
        var rule = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(5) };

        await limiter.CheckAsync(new RateLimitAttempt { Key = "expire-1" }, rule);
        await limiter.CheckAsync(new RateLimitAttempt { Key = "expire-2" }, rule);

        _timeProvider.Advance(TimeSpan.FromMinutes(6));

        var cleanedCount = await limiter.CleanupExpiredRowsAsync();
        Assert.That(cleanedCount, Is.EqualTo(2));

        await using var connection = await GetDataSource().OpenConnectionAsync();
        var count = await connection.ExecuteScalarAsync<int>("SELECT count(*) FROM ashlar_rate_limits");
        Assert.That(count, Is.Zero);
    }

    [Test]
    public async Task CheckAsyncRetriesIfCleanupDeletesRowBetweenInsertAndSelect()
    {
        var limiter = (PostgresAuthenticationRateLimiter)GetLimiter();
        var rule = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(5) };
        var attempt = new RateLimitAttempt { Key = "cleanup-race" };

        bool deleted = false;
        limiter.AfterInsertForTesting = async (connection, transaction, purpose, key, cancellationToken) =>
        {
            if (deleted)
            {
                return;
            }

            var command = new CommandDefinition(
                "DELETE FROM ashlar_rate_limits WHERE purpose = @purpose AND rate_limit_key = @key",
                new { purpose, key },
                transaction,
                cancellationToken: cancellationToken);
            await connection.ExecuteAsync(command);
            deleted = true;
        };

        try
        {
            var decision = await limiter.CheckAsync(attempt, rule);

            Assert.That(decision.IsAllowed, Is.True);
        }
        finally
        {
            limiter.AfterInsertForTesting = null;
        }
    }

    [Test]
    public async Task OpportunisticCleanupShouldRun()
    {
        var services = new ServiceCollection();
        services.AddAshlarPostgres(GetConnectionString());
        services.AddAshlarPostgresRateLimiting(options =>
        {
            options.CleanupInterval = TimeSpan.FromMinutes(1);
        });
        services.AddSingleton<TimeProvider>(_timeProvider);
        await using var provider = services.BuildServiceProvider();

        var limiter = (PostgresAuthenticationRateLimiter)provider.GetRequiredService<IAuthenticationRateLimiter>();
        var rule = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(5) };

        await limiter.CheckAsync(new RateLimitAttempt { Key = "cleanup-1" }, rule);

        _timeProvider.Advance(TimeSpan.FromMinutes(6));

        // This call should trigger opportunistic cleanup for "cleanup-1" because 6 min passed > 1 min interval
        await limiter.CheckAsync(new RateLimitAttempt { Key = "cleanup-2" }, rule);

        await using var connection = await GetDataSource().OpenConnectionAsync();
        var count = await WaitForRowCountAsync(connection, 1);

        Assert.That(count, Is.EqualTo(1));
    }

    [Test]
    public async Task AddAshlarPostgresDoesNotRegisterRateLimiterByDefault()
    {
        var services = new ServiceCollection();
        services.AddAshlarPostgres(GetConnectionString());
        services.AddSingleton<TimeProvider>(_timeProvider);
        await using var provider = services.BuildServiceProvider();

        var limiter = provider.GetService<IAuthenticationRateLimiter>();

        Assert.That(limiter, Is.Null);
    }

    [Test]
    public async Task AddAshlarPostgresRateLimitingReplacesDefaultIdentityRateLimiter()
    {
        var services = new ServiceCollection();
        services.AddAshlarIdentity();
        services.AddAshlarPostgres(GetConnectionString());
        services.AddAshlarPostgresRateLimiting();
        services.AddSingleton<TimeProvider>(_timeProvider);
        await using var provider = services.BuildServiceProvider();

        var limiter = provider.GetRequiredService<IAuthenticationRateLimiter>();

        Assert.That(limiter, Is.TypeOf<PostgresAuthenticationRateLimiter>());
    }

    [Test]
    public void AddAshlarPostgresRateLimitingRejectsInvalidCleanupInterval()
    {
        var services = new ServiceCollection();
        services.AddAshlarPostgres(GetConnectionString());
        services.AddAshlarPostgresRateLimiting(options =>
        {
            options.CleanupInterval = TimeSpan.Zero;
        });
        services.AddSingleton<TimeProvider>(_timeProvider);

        Assert.ThrowsAsync<OptionsValidationException>(async () => await ResolveRateLimiterAsync(services));
    }

    [Test]
    public void AddAshlarPostgresRateLimitingRejectsInvalidMaxCleanupRows()
    {
        var services = new ServiceCollection();
        services.AddAshlarPostgres(GetConnectionString());
        services.AddAshlarPostgresRateLimiting(options =>
        {
            options.MaxCleanupRows = 0;
        });
        services.AddSingleton<TimeProvider>(_timeProvider);

        Assert.ThrowsAsync<OptionsValidationException>(async () => await ResolveRateLimiterAsync(services));
    }

    [Test]
    public void ConstructorRejectsInvalidOptionsWhenOptionsValidationIsBypassed()
    {
        var options = Options.Create(new PostgresAuthenticationRateLimiterOptions
        {
            CleanupInterval = TimeSpan.Zero
        });

        Assert.Throws<ArgumentException>(() => _ = new PostgresAuthenticationRateLimiter(GetDataSource(), _timeProvider, options));
    }

    [Test]
    public void ValidateOptionsThrowsForNullOptions()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => PostgresAuthenticationRateLimiter.ValidateOptions(null!));
    }

    [Test]
    public async Task OpportunisticCleanupIgnoresCleanupFailures()
    {
        await using var dataSource = new NpgsqlDataSourceBuilder("Host=127.0.0.1;Port=1;Username=ashlar;Password=ashlar;Database=ashlar;Timeout=1").Build();
        var limiter = new PostgresAuthenticationRateLimiter(
            dataSource,
            _timeProvider,
            Options.Create(new PostgresAuthenticationRateLimiterOptions()));

        Assert.DoesNotThrowAsync(async () => await limiter.TryOpportunisticCleanupAsync());
    }

    [Test]
    public void OpportunisticCleanupCanBeTriggeredDirectly()
    {
        var limiter = new PostgresAuthenticationRateLimiter(
            GetDataSource(),
            _timeProvider,
            Options.Create(new PostgresAuthenticationRateLimiterOptions()));

        Assert.DoesNotThrowAsync(async () => await limiter.TryOpportunisticCleanupAsync());
    }

    private static async Task ResolveRateLimiterAsync(IServiceCollection services)
    {
        await using var provider = services.BuildServiceProvider();
        provider.GetRequiredService<IAuthenticationRateLimiter>();
    }

    private static async Task<int> WaitForRowCountAsync(NpgsqlConnection connection, int expectedCount)
    {
        int count = 0;
        for (int i = 0; i < 20; i++)
        {
            count = await connection.ExecuteScalarAsync<int>("SELECT count(*) FROM ashlar_rate_limits");
            if (count == expectedCount)
            {
                return count;
            }

            await Task.Delay(50);
        }

        return count;
    }
}









