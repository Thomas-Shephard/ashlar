using Ashlar.Testing;
using Ashlar.Auditing;
using Ashlar.Identity.Models.Administration;
using Ashlar.Identity.Models.AccountSecurity;
using Ashlar.Identity.Abstractions.Services;
using Ashlar.Identity.Abstractions.Repositories;
using Ashlar.Identity.Models.Sessions;
using Ashlar.Identity.Models.Tenants;
using Ashlar.ProviderContracts.DependencyInjection;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Identity.Abstractions.Transactions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using StackExchange.Redis;

namespace Ashlar.Redis.Tests.RateLimiting;

internal sealed class RedisAuthenticationRateLimitAdministrationTests : RedisTestBase
{
    private static readonly DateTimeOffset Start = DateTimeOffset.UtcNow;
    private FakeTimeProvider _timeProvider = null!;
    private ServiceProvider _provider = null!;
    private string _keyPrefix = null!;
    private AccountSecurityActorContext _actor = null!;

    public override async Task OneTimeSetUp()
    {
        await base.OneTimeSetUp();
        _timeProvider = new FakeTimeProvider(Start);
        _keyPrefix = $"ashlar:test:{Guid.NewGuid():N}";
        var services = new ServiceCollection();
        var actorId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        _actor = new AccountSecurityActorContext(actorId, TenantContext.Global, sessionId,
            FreshMfaVerificationProofFactory.Create(actorId, null, sessionId, Start, Start.AddMinutes(5),
                AccountSecurityActorContext.AdministrationReadProofPurpose), new AuditContext(actorId));
        var sessions = new Mock<IAuthenticationSessionRepository>();
        sessions.Setup(repository => repository.GetSessionAsync(sessionId, It.IsAny<CancellationToken>())).ReturnsAsync(new AuthenticationSession
        {
            Id = sessionId,
            UserId = actorId,
            TokenHash = "test",
            CreatedAt = Start,
            ExpiresAt = Start.AddYears(1)
        });
        services.AddAshlarIdentity();
        services.AddAshlarProviderScoped(_ => sessions.Object);
        services.AddSingleton<IAccountSecurityOperationAuthorizer, AllowOperations>();
        services.AddAshlarProviderScoped<IPersistentSecurityEventSink>(_ => new NoOpPersistentSecurityEventSink());
        services.AddAshlarRedisRateLimiting(GetConnection(), options => options.KeyPrefix = _keyPrefix);
        services.AddSingleton<TimeProvider>(_timeProvider);
        ConfigureDurableSecurityComposition(services, new NoOpPersistentSecurityEventSink());
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
        var administration = _provider.GetRequiredService<IAuthenticationRateLimitAdministrationReader>();
        var blockedKey = UniqueKey();
        var activeKey = UniqueKey();
        var rule = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(10), BlockDuration = TimeSpan.FromMinutes(30) };

        await limiter.CheckAsync(new RateLimitAttempt { Purpose = "login", Key = blockedKey }, rule);
        await limiter.CheckAsync(new RateLimitAttempt { Purpose = "login", Key = blockedKey }, rule);
        await limiter.CheckAsync(new RateLimitAttempt { Purpose = "login", Key = activeKey }, rule);
        await limiter.CheckAsync(new RateLimitAttempt { Purpose = "reset", Key = UniqueKey() }, rule);

        var blocked = await administration.SearchBucketsAsync(_actor, OperationalAdministrationScope.Global, new SearchAuthenticationRateLimitBucketsRequest
        {
            Purpose = "login",
            Status = AuthenticationRateLimitBucketStatus.Blocked,
            BlockedUntilFrom = Start + TimeSpan.FromMinutes(29),
            BlockedUntilTo = Start + TimeSpan.FromMinutes(31)
        });
        var active = await administration.SearchBucketsAsync(_actor, OperationalAdministrationScope.Global, new SearchAuthenticationRateLimitBucketsRequest
        {
            Purpose = "login",
            Status = AuthenticationRateLimitBucketStatus.Active,
            WindowStartFrom = Start,
            ExpiresFrom = Start + TimeSpan.FromMinutes(9)
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
    public async Task GetBucketAsyncRequiresPurposeMatch()
    {
        var limiter = _provider.GetRequiredService<IAuthenticationRateLimiter>();
        var administration = _provider.GetRequiredService<IAuthenticationRateLimitAdministrationReader>();
        var rawKey = $"raw-{Guid.NewGuid():N}@example.com";

        await limiter.CheckAsync(
            new RateLimitAttempt { Purpose = "detail", Key = rawKey },
            new RateLimitRule { PermitLimit = 5, Window = TimeSpan.FromMinutes(10) });
        var bucket = (await administration.SearchBucketsAsync(_actor, OperationalAdministrationScope.Global, new SearchAuthenticationRateLimitBucketsRequest { Purpose = "detail" })).Value!.Items.Single();

        var wrongPurposeLookup = await administration.GetBucketAsync(_actor, OperationalAdministrationScope.Global, new AuthenticationRateLimitBucketLookupRequest(bucket.BucketId, "other"));
        var lookup = await administration.GetBucketAsync(_actor, OperationalAdministrationScope.Global, new AuthenticationRateLimitBucketLookupRequest(bucket.BucketId, "detail"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(wrongPurposeLookup.Succeeded, Is.False);
            Assert.That(lookup.Value!.BucketId, Is.EqualTo(bucket.BucketId));
            Assert.That(lookup.Value.BucketId, Does.Not.Contain(rawKey));
        }
    }

    [Test]
    public void MutationServiceIsNotRegistered()
    {
        Assert.That(_provider.GetService<IAuthenticationRateLimitAdministrationService>(), Is.Null);
    }

    [TestCase("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")]
    [TestCase("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0")]
    [TestCase("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg")]
    [TestCase("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")]
    [TestCase("0123456789abcdef0123456789abcdef:../../0123456789abcdef01234567a")]
    public async Task GetBucketAsyncReturnsNotFoundForMalformedRedisBucketId(string bucketId)
    {
        var administration = _provider.GetRequiredService<IAuthenticationRateLimitAdministrationReader>();

        var lookup = await administration.GetBucketAsync(_actor, OperationalAdministrationScope.Global, new AuthenticationRateLimitBucketLookupRequest(bucketId, "detail"));

        Assert.That(lookup.Succeeded, Is.False);
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
        var administration = _provider.GetRequiredService<IAuthenticationRateLimitAdministrationReader>();
        await limiter.CheckAsync(
            new RateLimitAttempt { Purpose = "range", Key = UniqueKey() },
            new RateLimitRule { PermitLimit = 5, Window = TimeSpan.FromMinutes(10) });

        var futureWindow = await administration.SearchBucketsAsync(_actor, OperationalAdministrationScope.Global, new SearchAuthenticationRateLimitBucketsRequest
        {
            Purpose = "range",
            WindowStartFrom = Start + TimeSpan.FromMinutes(1)
        });
        var blockedRange = await administration.SearchBucketsAsync(_actor, OperationalAdministrationScope.Global, new SearchAuthenticationRateLimitBucketsRequest
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

    private ServiceProvider CreateProviderWithPersistentAudit(IPersistentSecurityEventSink sink)
    {
        var services = new ServiceCollection();
        var sessions = new Mock<IAuthenticationSessionRepository>();
        sessions.Setup(repository => repository.GetSessionAsync(_actor.CurrentSessionId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationSession
            {
                Id = _actor.CurrentSessionId,
                UserId = _actor.ActorUserId,
                TokenHash = "test",
                CreatedAt = Start,
                ExpiresAt = Start.AddYears(1)
            });
        services.AddAshlarIdentity();
        services.AddAshlarProviderScoped<IAuthenticationSessionRepository>(_ => sessions.Object);
        services.AddSingleton<IAccountSecurityOperationAuthorizer, AllowOperations>();
        services.AddAshlarProviderScoped<IPersistentSecurityEventSink>(_ => sink);
        services.AddAshlarRedisRateLimiting(GetConnection(), options => options.KeyPrefix = $"{_keyPrefix}:durable:{Guid.NewGuid():N}");
        services.AddSingleton<TimeProvider>(_timeProvider);
        ConfigureDurableSecurityComposition(services, sink);
        return services.BuildServiceProvider();
    }

    private static void ConfigureDurableSecurityComposition(IServiceCollection services, IPersistentSecurityEventSink sink)
    {
        var transactions = new TestDurableTransactionProvider();
        var composition = DurableTransactionComposition.Create(transactions, sink);
        services.Replace(ServiceDescriptor.Singleton(composition));
        services.Replace(ServiceDescriptor.Singleton(new SecurityEventFanOutSink(sink, transactionProvider: composition)));
        services.Replace(ServiceDescriptor.Singleton<ISecurityEventSink>(provider => provider.GetRequiredService<SecurityEventFanOutSink>()));
    }

    private sealed class TestDurableTransactionProvider : IAshlarTransactionProvider
    {
        public Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IAshlarTransaction>(new TestTransaction());
    }

    private sealed class TestTransaction : IAshlarTransaction
    {
        public Task CommitAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task RollbackAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public void OnCommitted(Func<CancellationToken, Task> action) => ArgumentNullException.ThrowIfNull(action);
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class NoOpPersistentSecurityEventSink : IPersistentSecurityEventSink
    {
        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class AllowOperations : IAccountSecurityOperationAuthorizer
    {
        public ValueTask<bool> AuthorizeAsync(AccountSecurityAuthorizationContext context, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(true);
    }
}
