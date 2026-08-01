using Ashlar.Identity.Abstractions.Services;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Microsoft.Extensions.DependencyInjection;

namespace Ashlar.ProviderContractTests.Identity.RateLimiting;

/// <summary>Tests safe bucket search, filtering, paging, lookup, and reset behavior.</summary>
public abstract class AuthenticationRateLimitAdministrationContractTests : ProviderContractFixture
{
    /// <summary>Current provider time used by administration assertions.</summary>
    protected abstract DateTimeOffset Now { get; }

    /// <summary>Whether the provider exposes rate-limit reset behavior.</summary>
    protected virtual bool SupportsReset => true;

    /// <summary>Advances the provider clock used for expiry decisions.</summary>
    /// <param name="duration">Amount by which to advance provider time.</param>
    protected abstract void AdvanceTime(TimeSpan duration);

    /// <summary>Adjusts requested time travel for provider clock precision.</summary>
    /// <param name="duration">Amount by which to advance provider time.</param>
    /// <returns>The duration the fixture should use for time travel.</returns>
    protected virtual TimeSpan TimeTravelDuration(TimeSpan duration) => duration;

    /// <summary>Allowed precision difference after provider time travel.</summary>
    protected virtual TimeSpan TimeTravelTolerance => TimeSpan.Zero;

    /// <summary>Verifies that bucket search combines purpose and blocked-status filters.</summary>
    [Test]
    public async Task SearchBucketsAsyncFiltersByPurposeAndStatus()
    {
        await using var scope = CreateAsyncScope();
        var actor = await CreateActorAsync(scope.ServiceProvider, AccountSecurityActorContext.AdministrationReadProofPurpose);
        var limiter = GetAuthenticationRateLimiter(scope.ServiceProvider);
        var administration = scope.ServiceProvider.GetRequiredService<IAuthenticationRateLimitAdministrationReader>();
        var blockedKey = UniqueKey();
        var activeKey = UniqueKey();
        var otherPurposeKey = UniqueKey();
        var rule = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(10), BlockDuration = TimeSpan.FromMinutes(30) };

        await limiter.CheckAsync(new RateLimitAttempt { Purpose = "login", Key = blockedKey }, rule);
        await limiter.CheckAsync(new RateLimitAttempt { Purpose = "login", Key = blockedKey }, rule);
        await limiter.CheckAsync(new RateLimitAttempt { Purpose = "login", Key = activeKey }, rule);
        await limiter.CheckAsync(new RateLimitAttempt { Purpose = "reset", Key = otherPurposeKey }, rule);

        var login = await administration.SearchBucketsAsync(actor, OperationalAdministrationScope.Global, new SearchAuthenticationRateLimitBucketsRequest { Purpose = "login" });
        var blocked = await administration.SearchBucketsAsync(actor, OperationalAdministrationScope.Global, new SearchAuthenticationRateLimitBucketsRequest
        {
            Purpose = "login",
            Status = AuthenticationRateLimitBucketStatus.Blocked
        });
        var active = await administration.SearchBucketsAsync(actor, OperationalAdministrationScope.Global, new SearchAuthenticationRateLimitBucketsRequest
        {
            Purpose = "login",
            Status = AuthenticationRateLimitBucketStatus.Active
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(login.Value!.Items, Has.Count.EqualTo(2));
            Assert.That(login.Value.Items.All(item => item.Purpose == "login"), Is.True);
            Assert.That(blocked.Value!.Items, Has.Count.EqualTo(1));
            Assert.That(blocked.Value.Items[0].Status, Is.EqualTo(AuthenticationRateLimitBucketStatus.Blocked));
            Assert.That(active.Value!.Items, Has.Count.EqualTo(1));
            Assert.That(active.Value.Items[0].Status, Is.EqualTo(AuthenticationRateLimitBucketStatus.Active));
        }
    }

    /// <summary>Verifies that omitting purpose includes buckets from every purpose.</summary>
    [Test]
    public async Task SearchBucketsAsyncAllowsUnscopedPurposeBrowse()
    {
        await using var scope = CreateAsyncScope();
        var actor = await CreateActorAsync(scope.ServiceProvider, AccountSecurityActorContext.AdministrationReadProofPurpose);
        var limiter = GetAuthenticationRateLimiter(scope.ServiceProvider);
        var administration = scope.ServiceProvider.GetRequiredService<IAuthenticationRateLimitAdministrationReader>();
        var rule = new RateLimitRule { PermitLimit = 5, Window = TimeSpan.FromMinutes(10) };

        await limiter.CheckAsync(new RateLimitAttempt { Purpose = "browse-one", Key = UniqueKey() }, rule);
        await limiter.CheckAsync(new RateLimitAttempt { Purpose = "browse-two", Key = UniqueKey() }, rule);

        var result = await administration.SearchBucketsAsync(actor, OperationalAdministrationScope.Global, new SearchAuthenticationRateLimitBucketsRequest { Limit = 10 });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value!.Items.Select(item => item.Purpose), Does.Contain("browse-one"));
            Assert.That(result.Value.Items.Select(item => item.Purpose), Does.Contain("browse-two"));
        }
    }

    /// <summary>Verifies that date filtering occurs before buckets are stably paged.</summary>
    [Test]
    public async Task SearchBucketsAsyncAppliesDateFiltersAndStablePaging()
    {
        await using var scope = CreateAsyncScope();
        var actor = await CreateActorAsync(scope.ServiceProvider, AccountSecurityActorContext.AdministrationReadProofPurpose);
        var limiter = GetAuthenticationRateLimiter(scope.ServiceProvider);
        var administration = scope.ServiceProvider.GetRequiredService<IAuthenticationRateLimitAdministrationReader>();
        var rule = new RateLimitRule { PermitLimit = 5, Window = TimeSpan.FromMinutes(10) };

        await limiter.CheckAsync(new RateLimitAttempt { Purpose = "paging", Key = UniqueKey() }, rule);
        AdvanceTime(TimeTravelDuration(TimeSpan.FromMinutes(1)));
        var secondStart = Now;
        await limiter.CheckAsync(new RateLimitAttempt { Purpose = "paging", Key = UniqueKey() }, rule);
        await limiter.CheckAsync(new RateLimitAttempt { Purpose = "paging", Key = UniqueKey() }, rule);

        var filtered = await administration.SearchBucketsAsync(actor, OperationalAdministrationScope.Global, new SearchAuthenticationRateLimitBucketsRequest
        {
            Purpose = "paging",
            WindowStartFrom = secondStart,
            WindowStartTo = secondStart + TimeTravelTolerance,
            ExpiresFrom = secondStart + rule.Window,
            ExpiresTo = secondStart + rule.Window + TimeTravelTolerance,
            Limit = 1
        });
        var secondPage = await administration.SearchBucketsAsync(actor, OperationalAdministrationScope.Global, new SearchAuthenticationRateLimitBucketsRequest
        {
            Purpose = "paging",
            WindowStartFrom = secondStart,
            Limit = 1,
            Offset = 1
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(filtered.Value!.Items, Has.Count.EqualTo(1));
            Assert.That(filtered.Value.HasMore, Is.True);
            Assert.That(secondPage.Value!.Items, Has.Count.EqualTo(1));
            Assert.That(secondPage.Value.Items[0].BucketId, Is.Not.EqualTo(filtered.Value.Items[0].BucketId));
        }
    }

    /// <summary>Verifies that expiry filtering uses the requested comparison time.</summary>
    [Test]
    public async Task SearchBucketsAsyncFiltersExpiredBuckets()
    {
        await using var scope = CreateAsyncScope();
        var actor = await CreateActorAsync(scope.ServiceProvider, AccountSecurityActorContext.AdministrationReadProofPurpose);
        var limiter = GetAuthenticationRateLimiter(scope.ServiceProvider);
        var administration = scope.ServiceProvider.GetRequiredService<IAuthenticationRateLimitAdministrationReader>();
        var rule = new RateLimitRule { PermitLimit = 5, Window = TimeTravelDuration(TimeSpan.FromMinutes(1)) };

        await limiter.CheckAsync(new RateLimitAttempt { Purpose = "expired", Key = UniqueKey() }, rule);
        AdvanceTime(TimeTravelDuration(TimeSpan.FromMinutes(2)));

        var expired = await administration.SearchBucketsAsync(actor, OperationalAdministrationScope.Global, new SearchAuthenticationRateLimitBucketsRequest
        {
            Purpose = "expired",
            Status = AuthenticationRateLimitBucketStatus.Expired,
            ExpiresTo = Now
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(expired.Value!.Items, Has.Count.EqualTo(1));
            Assert.That(expired.Value.Items[0].Status, Is.EqualTo(AuthenticationRateLimitBucketStatus.Expired));
        }
    }

    /// <summary>Verifies that bucket lookup returns its policy state without raw key material.</summary>
    [Test]
    public async Task GetBucketAsyncReturnsSafeLookup()
    {
        await using var scope = CreateAsyncScope();
        var actor = await CreateActorAsync(scope.ServiceProvider, AccountSecurityActorContext.AdministrationReadProofPurpose);
        var limiter = GetAuthenticationRateLimiter(scope.ServiceProvider);
        var administration = scope.ServiceProvider.GetRequiredService<IAuthenticationRateLimitAdministrationReader>();
        var rawKey = $"raw-email-{Guid.NewGuid():N}@example.com";

        await limiter.CheckAsync(
            new RateLimitAttempt { Purpose = "detail", Key = rawKey },
            new RateLimitRule { PermitLimit = 5, Window = TimeSpan.FromMinutes(10) });

        var search = await administration.SearchBucketsAsync(actor, OperationalAdministrationScope.Global, new SearchAuthenticationRateLimitBucketsRequest { Purpose = "detail" });
        var summary = search.Value!.Items.Single();
        var lookup = await administration.GetBucketAsync(actor, OperationalAdministrationScope.Global, new AuthenticationRateLimitBucketLookupRequest(summary.BucketId, "detail"));
        var mismatch = await administration.GetBucketAsync(actor, OperationalAdministrationScope.Global, new AuthenticationRateLimitBucketLookupRequest("not-the-bucket", "detail"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(lookup.Succeeded, Is.True);
            Assert.That(lookup.Value!.BucketId, Is.EqualTo(summary.BucketId));
            Assert.That(lookup.Value.BucketId, Does.Not.Contain(rawKey));
            Assert.That(lookup.Value.Purpose, Is.EqualTo("detail"));
            Assert.That(mismatch.Succeeded, Is.False);
        }
    }

    /// <summary>Verifies that reset deletes a stored bucket once and reports later absence.</summary>
    [Test]
    public async Task ResetBucketAsyncDeletesExistingBucketAndReportsMissingBucket()
    {
        if (!SupportsReset) Assert.Ignore("This provider exposes read-only rate-limit administration.");

        await using var scope = CreateAsyncScope();
        var actor = await CreateActorAsync(scope.ServiceProvider, AccountSecurityActorContext.AdministrationReadProofPurpose);
        var mutationActor = await CreateActorAsync(scope.ServiceProvider, IAccountSecurityAdministrationService.ProofPurpose);
        var limiter = GetAuthenticationRateLimiter(scope.ServiceProvider);
        var administration = scope.ServiceProvider.GetRequiredService<IAuthenticationRateLimitAdministrationReader>();
        var mutations = scope.ServiceProvider.GetRequiredService<IAuthenticationRateLimitAdministrationService>();
        var rawKey = UniqueKey();

        await limiter.CheckAsync(
            new RateLimitAttempt { Purpose = "reset", Key = rawKey },
            new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(10) });
        var bucket = (await administration.SearchBucketsAsync(actor, OperationalAdministrationScope.Global, new SearchAuthenticationRateLimitBucketsRequest { Purpose = "reset" })).Value!.Items.Single();

        var reset = await mutations.ResetBucketAsync(mutationActor, OperationalAdministrationScope.Global, new ResetAuthenticationRateLimitBucketRequest(bucket.BucketId, "reset"));
        var missing = await mutations.ResetBucketAsync(mutationActor, OperationalAdministrationScope.Global, new ResetAuthenticationRateLimitBucketRequest(bucket.BucketId, "reset"));
        var providerMissing = await scope.ServiceProvider.GetRequiredService<IAuthenticationRateLimitAdministrationRepository>()
            .ResetBucketAsync(new ResetAuthenticationRateLimitBucketRequest(bucket.BucketId, "reset"));
        var afterReset = await administration.GetBucketAsync(actor, OperationalAdministrationScope.Global, new AuthenticationRateLimitBucketLookupRequest(bucket.BucketId, "reset"));

        using (Assert.EnterMultipleScope())
        {
            if (reset.Value!.Status == AuthenticationRateLimitBucketResetStatus.Failed)
            {
                Assert.That(missing.Value!.Status, Is.EqualTo(AuthenticationRateLimitBucketResetStatus.Failed));
                Assert.That(afterReset.Succeeded, Is.True);
            }
            else
            {
                Assert.That(reset.Value.Status, Is.EqualTo(AuthenticationRateLimitBucketResetStatus.Reset));
                Assert.That(missing.Value!.Status, Is.EqualTo(AuthenticationRateLimitBucketResetStatus.NotFound));
                Assert.That(providerMissing, Is.False);
                Assert.That(afterReset.Succeeded, Is.False);
            }
        }
    }

    /// <summary>Verifies that bucket search exposes hashes instead of raw rate-limit keys.</summary>
    [Test]
    public async Task SearchBucketsAsyncDoesNotExposeRawSensitiveInputs()
    {
        await using var scope = CreateAsyncScope();
        var actor = await CreateActorAsync(scope.ServiceProvider, AccountSecurityActorContext.AdministrationReadProofPurpose);
        var limiter = GetAuthenticationRateLimiter(scope.ServiceProvider);
        var administration = scope.ServiceProvider.GetRequiredService<IAuthenticationRateLimitAdministrationReader>();
        var sensitive = $"user-{Guid.NewGuid():N}@example.com";

        await limiter.CheckAsync(
            new RateLimitAttempt { Purpose = "safe", Key = sensitive },
            new RateLimitRule { PermitLimit = 5, Window = TimeSpan.FromMinutes(10) });

        var search = await administration.SearchBucketsAsync(actor, OperationalAdministrationScope.Global, new SearchAuthenticationRateLimitBucketsRequest { Purpose = "safe" });
        var bucket = search.Value!.Items.Single();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(bucket.BucketId, Does.Not.Contain(sensitive));
            Assert.That(bucket.BucketId, Does.Not.Contain("user-"));
            Assert.That(bucket.BucketId, Does.Not.Contain("@example.com"));
        }
    }

    private protected static async Task<AccountSecurityActorContext> CreateActorAsync(IServiceProvider services, string purpose)
    {
        var users = services.GetService<IUserRepository>();
        var user = users is null
            ? new AshlarUser { Id = Guid.NewGuid(), DisplayEmail = $"{Guid.NewGuid():N}@example.test", AccountState = UserAccountState.Active }
            : await CreateUserAsync(users);
        var token = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
        var proofNow = services.GetRequiredService<TimeProvider>().GetUtcNow();
        var session = new AuthenticationSession
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            TokenHash = HashToken(services, token),
            CreatedAt = proofNow,
            AdditionalVerificationAt = proofNow - TimeSpan.FromSeconds(1),
            ExpiresAt = proofNow.AddYears(1)
        };
        return new AccountSecurityActorContext(user.Id, TenantContext.Global, session.Id,
            await CreateFreshMfaProofAsync(services, session, token, purpose),
            new AuditContext(user.Id));
    }

    private static string UniqueKey() => $"admin-contract-{Guid.NewGuid():N}";
}
