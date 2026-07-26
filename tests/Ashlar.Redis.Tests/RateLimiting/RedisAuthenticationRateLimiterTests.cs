using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using StackExchange.Redis;

namespace Ashlar.Redis.Tests.RateLimiting;

internal sealed class RedisAuthenticationRateLimiterTests : RedisTestBase
{
    private static readonly DateTimeOffset Start = new(2026, 5, 22, 12, 0, 0, TimeSpan.Zero);
    private FakeTimeProvider _timeProvider = null!;
    private ServiceProvider _provider = null!;
    private string _keyPrefix = null!;

    public override async Task OneTimeSetUp()
    {
        await base.OneTimeSetUp();
        _timeProvider = new FakeTimeProvider(Start);
        _keyPrefix = $"ashlar:test:{Guid.NewGuid():N}";
        var services = new ServiceCollection();
        services.AddAshlarRedisRateLimiting(GetConnection(), options => options.KeyPrefix = _keyPrefix);
        services.AddSingleton<TimeProvider>(_timeProvider);
        _provider = services.BuildServiceProvider();
    }

    [OneTimeTearDown]
    public async Task DisposeProviderAsync()
    {
        if (_provider != null)
        {
            await _provider.DisposeAsync();
        }
    }

    [SetUp]
    public async Task SetUp()
    {
        _timeProvider.SetUtcNow(Start);
        await FlushDatabaseAsync();
    }

    [Test]
    public async Task CheckAsyncConcurrentCallsShareAtomicLimit()
    {
        var limiter = _provider.GetRequiredService<IAuthenticationRateLimiter>();
        var attempt = new RateLimitAttempt { Purpose = "login", Key = "shared-user" };
        var rule = new RateLimitRule { PermitLimit = 10, Window = TimeSpan.FromMinutes(5) };

        var decisions = await Task.WhenAll(Enumerable.Range(0, 50).Select(_ => limiter.CheckAsync(attempt, rule)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(decisions.Count(decision => decision.IsAllowed), Is.EqualTo(10));
            Assert.That(decisions.Count(decision => !decision.IsAllowed), Is.EqualTo(40));
        }
    }

    [Test]
    public async Task CheckAsyncUsesHashedNamespacedKeys()
    {
        var limiter = _provider.GetRequiredService<IAuthenticationRateLimiter>();

        await limiter.CheckAsync(
            new RateLimitAttempt { Purpose = "login", Key = "raw@example.com" },
            new RateLimitRule { PermitLimit = 2, Window = TimeSpan.FromMinutes(5) });

        var server = GetConnection().GetServer(GetConnection().GetEndPoints().Single());
        var keys = server.Keys(pattern: $"{_keyPrefix}:auth:*").Select(key => key.ToString()).ToArray();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(keys, Has.Length.EqualTo(1));
            Assert.That(keys[0], Does.StartWith($"{_keyPrefix}:auth:"));
            Assert.That(keys[0], Does.Not.Contain("raw@example.com"));
            Assert.That(keys[0], Does.Not.Contain("login"));
        }
    }

    [Test]
    public async Task AddAshlarRedisRateLimitingWithConnectionStringRegistersUsableConnection()
    {
        var prefix = $"ashlar:test:{Guid.NewGuid():N}";
        var services = new ServiceCollection();
        services.AddAshlarRedisRateLimiting(GetConnectionString(), options => options.KeyPrefix = prefix);
        await using var provider = services.BuildServiceProvider();

        var limiter = provider.GetRequiredService<IAuthenticationRateLimiter>();
        var decision = await limiter.CheckAsync(
            new RateLimitAttempt { Key = "connection-string" },
            new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(1) });

        Assert.That(decision.IsAllowed, Is.True);
    }

    [Test]
    public async Task CheckAsyncExpiresRedisKeyAfterReset()
    {
        var keyPrefix = $"ashlar:test:{Guid.NewGuid():N}";
        var services = new ServiceCollection();
        services.AddAshlarRedisRateLimiting(GetConnection(), options =>
        {
            options.KeyPrefix = keyPrefix;
            options.ExpirationSkew = TimeSpan.Zero;
        });
        services.AddSingleton<TimeProvider>(_timeProvider);
        await using var provider = services.BuildServiceProvider();
        var limiter = provider.GetRequiredService<IAuthenticationRateLimiter>();
        var rule = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMilliseconds(50) };

        await limiter.CheckAsync(new RateLimitAttempt { Key = "expiring" }, rule);
        await Task.Delay(TimeSpan.FromMilliseconds(250));

        var server = GetConnection().GetServer(GetConnection().GetEndPoints().Single());
        var keys = server.Keys(pattern: $"{keyPrefix}:auth:*").ToArray();

        Assert.That(keys, Is.Empty);
    }

    [Test]
    public async Task CheckAsyncUsesRedisTimeDespiteSlowApplicationClock()
    {
        var limiter = _provider.GetRequiredService<IAuthenticationRateLimiter>();
        await using var slowNode = CreateProvider(new FakeTimeProvider(DateTimeOffset.UnixEpoch));
        var attempt = new RateLimitAttempt { Purpose = "login", Key = "slow-clock" };
        var rule = new RateLimitRule { PermitLimit = 2, Window = TimeSpan.FromMinutes(5) };

        var key = RedisRateLimitKeyBuilder.Build(_keyPrefix, attempt.Purpose, attempt.Key);
        var database = GetConnection().GetDatabase();
        var redisBefore = await GetRedisTimeAsync(database);
        await limiter.CheckAsync(attempt, rule);
        var redisAfter = await GetRedisTimeAsync(database);
        var originalWindowStart = (long)await database.HashGetAsync(key, "windowStart");
        var decision = await slowNode.GetRequiredService<IAuthenticationRateLimiter>().CheckAsync(attempt, rule);
        var windowStart = (long)await database.HashGetAsync(key, "windowStart");
        var ttl = await database.KeyTimeToLiveAsync(key);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(decision.Remaining, Is.Zero);
            Assert.That(windowStart, Is.EqualTo(originalWindowStart));
            Assert.That(DateTimeOffset.FromUnixTimeMilliseconds(windowStart), Is.InRange(redisBefore, redisAfter));
            Assert.That(decision.WindowResetAt, Is.EqualTo(DateTimeOffset.FromUnixTimeMilliseconds(windowStart) + rule.Window));
            Assert.That(ttl, Is.Not.Null.And.InRange(TimeSpan.Zero, rule.Window + TimeSpan.FromSeconds(5)));
        }
    }

    [Test]
    public async Task CheckAsyncFastApplicationClockCannotExpireBlockEarly()
    {
        var limiter = _provider.GetRequiredService<IAuthenticationRateLimiter>();
        await using var fastNode = CreateProvider(new FakeTimeProvider(DateTimeOffset.MaxValue));
        var attempt = new RateLimitAttempt { Purpose = "login", Key = "fast-clock" };
        var rule = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(5), BlockDuration = TimeSpan.FromMinutes(15) };

        await limiter.CheckAsync(attempt, rule);
        var blocked = await limiter.CheckAsync(attempt, rule);
        var stillBlocked = await fastNode.GetRequiredService<IAuthenticationRateLimiter>().CheckAsync(attempt, rule);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(stillBlocked.IsAllowed, Is.False);
            Assert.That(stillBlocked.RetryAfter, Is.EqualTo(blocked.RetryAfter));
        }
    }

    private ServiceProvider CreateProvider(TimeProvider timeProvider)
    {
        var services = new ServiceCollection();
        services.AddSingleton(timeProvider);
        services.AddAshlarRedisRateLimiting(GetConnection(), options => options.KeyPrefix = _keyPrefix);
        return services.BuildServiceProvider();
    }

    private static async Task<DateTimeOffset> GetRedisTimeAsync(IDatabase database)
    {
        var time = (RedisResult[])(await database.ExecuteAsync("TIME"))!;
        return DateTimeOffset.FromUnixTimeMilliseconds((long)time[0] * 1000 + (long)time[1] / 1000);
    }
}
