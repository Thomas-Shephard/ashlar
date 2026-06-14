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

        var wrongPurposeDetail = await administration.GetBucketAsync(new AuthenticationRateLimitBucketDetailRequest(bucket.BucketId, "other"));
        var wrongPurposeReset = await administration.ResetBucketAsync(new ResetAuthenticationRateLimitBucketRequest(bucket.BucketId, "other", new AuditContext(Guid.NewGuid())));
        var detail = await administration.GetBucketAsync(new AuthenticationRateLimitBucketDetailRequest(bucket.BucketId, "detail"));
        var reset = await administration.ResetBucketAsync(new ResetAuthenticationRateLimitBucketRequest(bucket.BucketId, "detail", new AuditContext(Guid.NewGuid())));
        var missing = await administration.ResetBucketAsync(new ResetAuthenticationRateLimitBucketRequest(bucket.BucketId, "detail", new AuditContext(Guid.NewGuid())));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(wrongPurposeDetail.Succeeded, Is.False);
            Assert.That(wrongPurposeReset.Value!.Status, Is.EqualTo(AuthenticationRateLimitBucketResetStatus.NotFound));
            Assert.That(detail.Value!.BucketId, Is.EqualTo(bucket.BucketId));
            Assert.That(detail.Value.BucketId, Does.Not.Contain(rawKey));
            Assert.That(reset.Value!.Status, Is.EqualTo(AuthenticationRateLimitBucketResetStatus.Reset));
            Assert.That(missing.Value!.Status, Is.EqualTo(AuthenticationRateLimitBucketResetStatus.NotFound));
        }
    }

    [Test]
    public async Task RepositorySkipsMalformedRowsAndCanProjectExpiredRows()
    {
        var database = GetConnection().GetDatabase();
        var prefix = _keyPrefix.TrimEnd(':');
        var malformedKey = (RedisKey)$"{prefix}:auth:malformed";
        var expiredKey = (RedisKey)$"{prefix}:auth:expired";
        await database.HashSetAsync(malformedKey, [new HashEntry("purpose", "malformed")]);
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
        var missing = await repository.GetBucketAsync(new AuthenticationRateLimitBucketDetailRequest("missing", "expired"), Start);

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

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new RedisAuthenticationRateLimitAdministrationRepository((IConnectionMultiplexer)null!, options));
            Assert.Throws<ArgumentNullException>(() => _ = new RedisAuthenticationRateLimitAdministrationRepository(GetConnection(), null!));
        }
    }

    private static string UniqueKey() => $"redis-admin-{Guid.NewGuid():N}";
}
