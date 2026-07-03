using Ashlar.Auditing;
using Ashlar.Identity.Models.Administration;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using StackExchange.Redis;

namespace Ashlar.Redis.Tests.RateLimiting;

internal sealed class RedisAuthenticationRateLimitAdministrationTests : RedisTestBase
{
    private static readonly DateTimeOffset Start = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);
    private FakeTimeProvider _timeProvider = null!;
    private ServiceProvider _provider = null!;
    private string _keyPrefix = null!;

    public override async Task OneTimeSetUp()
    {
        await base.OneTimeSetUp();
        _timeProvider = new FakeTimeProvider(Start);
        _keyPrefix = $"ashlar:test:{Guid.NewGuid():N}";
        var services = new ServiceCollection();
        services.AddAshlarIdentity();
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
    public async Task SearchBucketsAsyncFiltersByPurposeStatusAndDatesWithoutPhysicalRedisKey()
    {
        var limiter = _provider.GetRequiredService<IAuthenticationRateLimiter>();
        var administration = _provider.GetRequiredService<IAuthenticationRateLimitAdministrationService>();
        var blockedKey = UniqueKey();
        var activeKey = UniqueKey();
        var rule = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(10), BlockDuration = TimeSpan.FromMinutes(30) };

        await limiter.CheckAsync(new RateLimitAttempt { Purpose = "login", Key = blockedKey }, rule);
        await limiter.CheckAsync(new RateLimitAttempt { Purpose = "login", Key = blockedKey }, rule);
        await limiter.CheckAsync(new RateLimitAttempt { Purpose = "login", Key = activeKey }, rule);
        await limiter.CheckAsync(new RateLimitAttempt { Purpose = "reset", Key = UniqueKey() }, rule);

        var blocked = await administration.SearchBucketsAsync(new SearchAuthenticationRateLimitBucketsRequest
        {
            Purpose = "login",
            Status = AuthenticationRateLimitBucketStatus.Blocked,
            BlockedUntilFrom = Start + TimeSpan.FromMinutes(29),
            BlockedUntilTo = Start + TimeSpan.FromMinutes(31)
        });
        var active = await administration.SearchBucketsAsync(new SearchAuthenticationRateLimitBucketsRequest
        {
            Purpose = "login",
            Status = AuthenticationRateLimitBucketStatus.Active,
            WindowStartFrom = Start,
            ExpiresFrom = Start + rule.Window
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(blocked.Value!.Items, Has.Count.EqualTo(1));
            Assert.That(active.Value!.Items, Has.Count.EqualTo(1));
            Assert.That(blocked.Value.Items[0].BucketId, Does.Not.StartWith(_keyPrefix));
            Assert.That(blocked.Value.Items[0].BucketId, Does.Not.Contain("auth:"));
            Assert.That(blocked.Value.Items[0].BucketId, Does.Not.Contain(blockedKey));
            Assert.That(blocked.Value.Items[0].BucketId, Does.Match("^[0-9a-f]{64}$"));
        }
    }

    [Test]
    public async Task GetBucketAsyncAndResetBucketAsyncRequirePurposeMatch()
    {
        var limiter = _provider.GetRequiredService<IAuthenticationRateLimiter>();
        var administration = _provider.GetRequiredService<IAuthenticationRateLimitAdministrationService>();
        var rawKey = $"raw-{Guid.NewGuid():N}@example.com";

        await limiter.CheckAsync(
            new RateLimitAttempt { Purpose = "detail", Key = rawKey },
            new RateLimitRule { PermitLimit = 5, Window = TimeSpan.FromMinutes(10) });
        var bucket = (await administration.SearchBucketsAsync(new SearchAuthenticationRateLimitBucketsRequest { Purpose = "detail" })).Value!.Items.Single();

        var wrongPurposeLookup = await administration.GetBucketAsync(new AuthenticationRateLimitBucketLookupRequest(bucket.BucketId, "other"));
        var wrongPurposeReset = await administration.ResetBucketAsync(new ResetAuthenticationRateLimitBucketRequest(bucket.BucketId, "other", new AuditContext(Guid.NewGuid())));
        var lookup = await administration.GetBucketAsync(new AuthenticationRateLimitBucketLookupRequest(bucket.BucketId, "detail"));
        var reset = await administration.ResetBucketAsync(new ResetAuthenticationRateLimitBucketRequest(bucket.BucketId, "detail", new AuditContext(Guid.NewGuid())));
        var missing = await administration.ResetBucketAsync(new ResetAuthenticationRateLimitBucketRequest(bucket.BucketId, "detail", new AuditContext(Guid.NewGuid())));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(wrongPurposeLookup.Succeeded, Is.False);
            Assert.That(wrongPurposeReset.Value!.Status, Is.EqualTo(AuthenticationRateLimitBucketResetStatus.NotFound));
            Assert.That(lookup.Value!.BucketId, Is.EqualTo(bucket.BucketId));
            Assert.That(lookup.Value.BucketId, Does.Not.Contain(rawKey));
            Assert.That(reset.Value!.Status, Is.EqualTo(AuthenticationRateLimitBucketResetStatus.Reset));
            Assert.That(missing.Value!.Status, Is.EqualTo(AuthenticationRateLimitBucketResetStatus.NotFound));
        }
    }

    [TestCase("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")]
    [TestCase("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0")]
    [TestCase("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg")]
    [TestCase("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")]
    [TestCase("0123456789abcdef0123456789abcdef:../../0123456789abcdef01234567a")]
    public async Task GetBucketAsyncReturnsNotFoundForMalformedRedisBucketId(string bucketId)
    {
        var administration = _provider.GetRequiredService<IAuthenticationRateLimitAdministrationService>();

        var lookup = await administration.GetBucketAsync(new AuthenticationRateLimitBucketLookupRequest(bucketId, "detail"));

        Assert.That(lookup.Succeeded, Is.False);
    }

    [TestCase("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")]
    [TestCase("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0")]
    [TestCase("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg")]
    [TestCase("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")]
    [TestCase("0123456789abcdef0123456789abcdef:../../0123456789abcdef01234567a")]
    public async Task ResetBucketAsyncReturnsNotFoundForMalformedRedisBucketIdAndDoesNotDeleteExistingBucket(string bucketId)
    {
        var limiter = _provider.GetRequiredService<IAuthenticationRateLimiter>();
        var administration = _provider.GetRequiredService<IAuthenticationRateLimitAdministrationService>();
        await limiter.CheckAsync(
            new RateLimitAttempt { Purpose = "detail", Key = UniqueKey() },
            new RateLimitRule { PermitLimit = 5, Window = TimeSpan.FromMinutes(10) });
        var existing = (await administration.SearchBucketsAsync(new SearchAuthenticationRateLimitBucketsRequest { Purpose = "detail" })).Value!.Items.Single();

        var reset = await administration.ResetBucketAsync(new ResetAuthenticationRateLimitBucketRequest(bucketId, "detail", new AuditContext(Guid.NewGuid())));
        var existingLookup = await administration.GetBucketAsync(new AuthenticationRateLimitBucketLookupRequest(existing.BucketId, "detail"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(reset.Value!.Status, Is.EqualTo(AuthenticationRateLimitBucketResetStatus.NotFound));
            Assert.That(existingLookup.Value!.BucketId, Is.EqualTo(existing.BucketId));
        }
    }

    [Test]
    public async Task RepositorySkipsMalformedRowsAndCanProjectExpiredRows()
    {
        var database = GetConnection().GetDatabase();
        var prefix = _keyPrefix.TrimEnd(':');
        var malformedSuffixKey = (RedisKey)$"{prefix}:auth:malformed";
        var malformedHashKey = (RedisKey)$"{prefix}:auth:{new string('0', 64)}";
        var expiredKey = (RedisKey)$"{prefix}:auth:{new string('1', 64)}";
        await database.HashSetAsync(malformedSuffixKey,
        [
            new HashEntry("purpose", "malformed"),
            new HashEntry("count", 1),
            new HashEntry("windowStart", Start.ToUnixTimeMilliseconds()),
            new HashEntry("expiresAt", (Start + TimeSpan.FromMinutes(1)).ToUnixTimeMilliseconds())
        ]);
        await database.HashSetAsync(malformedHashKey, [new HashEntry("purpose", "malformed")]);
        await database.HashSetAsync(expiredKey,
        [
            new HashEntry("purpose", "expired"),
            new HashEntry("count", 1),
            new HashEntry("windowStart", Start.ToUnixTimeMilliseconds()),
            new HashEntry("expiresAt", (Start - TimeSpan.FromMinutes(1)).ToUnixTimeMilliseconds())
        ]);
        var repository = new RedisAuthenticationRateLimitAdministrationRepository(
            GetConnection(),
            Options.Create(new RedisAuthenticationRateLimiterOptions { KeyPrefix = _keyPrefix }));

        var malformed = await repository.SearchBucketsAsync(new SearchAuthenticationRateLimitBucketsRequest { Purpose = "malformed" }, Start);
        var expired = await repository.SearchBucketsAsync(new SearchAuthenticationRateLimitBucketsRequest { Purpose = "expired", Status = AuthenticationRateLimitBucketStatus.Expired }, Start);
        var missing = await repository.GetBucketAsync(new AuthenticationRateLimitBucketLookupRequest("missing", "expired"), Start);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(malformed, Is.Empty);
            Assert.That(expired, Has.Count.EqualTo(1));
            Assert.That(expired[0].Status, Is.EqualTo(AuthenticationRateLimitBucketStatus.Expired));
            Assert.That(missing, Is.Null);
        }
    }

    [Test]
    public async Task SearchBucketsAsyncAppliesNegativeRangeFilters()
    {
        var limiter = _provider.GetRequiredService<IAuthenticationRateLimiter>();
        var administration = _provider.GetRequiredService<IAuthenticationRateLimitAdministrationService>();
        await limiter.CheckAsync(
            new RateLimitAttempt { Purpose = "range", Key = UniqueKey() },
            new RateLimitRule { PermitLimit = 5, Window = TimeSpan.FromMinutes(10) });

        var futureWindow = await administration.SearchBucketsAsync(new SearchAuthenticationRateLimitBucketsRequest
        {
            Purpose = "range",
            WindowStartFrom = Start + TimeSpan.FromMinutes(1)
        });
        var blockedRange = await administration.SearchBucketsAsync(new SearchAuthenticationRateLimitBucketsRequest
        {
            Purpose = "range",
            BlockedUntilFrom = Start
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(futureWindow.Value!.Items, Is.Empty);
            Assert.That(blockedRange.Value!.Items, Is.Empty);
        }
    }

    [Test]
    public void PublicRepositoryConstructorValidatesInputs()
    {
        var options = Options.Create(new RedisAuthenticationRateLimiterOptions { KeyPrefix = _keyPrefix });
        var invalidOptions = Options.Create(new RedisAuthenticationRateLimiterOptions { KeyPrefix = "invalid prefix" });

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new RedisAuthenticationRateLimitAdministrationRepository((IConnectionMultiplexer)null!, options));
            Assert.Throws<ArgumentNullException>(() => _ = new RedisAuthenticationRateLimitAdministrationRepository(GetConnection(), null!));
            Assert.Throws<ArgumentException>(() => _ = new RedisAuthenticationRateLimitAdministrationRepository(GetConnection(), invalidOptions));
        }
    }

    [Test]
    public void WrapperRepositoryConstructorRejectsInvalidOptions()
    {
        var connection = new RedisAuthenticationRateLimiterConnection(new Lazy<Task<IConnectionMultiplexer>>(() => Task.FromResult(GetConnection())), false);
        var options = Options.Create(new RedisAuthenticationRateLimiterOptions());

        Assert.Throws<ArgumentException>(() => _ = new RedisAuthenticationRateLimitAdministrationRepository(connection, options));
    }

    private static string UniqueKey() => $"redis-admin-{Guid.NewGuid():N}";
}
