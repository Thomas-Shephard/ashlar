using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Microsoft.Extensions.DependencyInjection;

namespace Ashlar.ProviderContractTests.Identity.RateLimiting;

internal abstract class AuthenticationRateLimitAdministrationContractTests : ProviderContractFixture
{
    protected abstract DateTimeOffset Now { get; }

    protected abstract void AdvanceTime(TimeSpan duration);

    [Test]
    public async Task SearchBucketsAsyncFiltersByPurposeAndStatus()
    {
        await using var scope = CreateAsyncScope();
        var limiter = GetAuthenticationRateLimiter(scope.ServiceProvider);
        var administration = scope.ServiceProvider.GetRequiredService<IAuthenticationRateLimitAdministrationService>();
        var blockedKey = UniqueKey();
        var activeKey = UniqueKey();
        var otherPurposeKey = UniqueKey();
        var rule = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(10), BlockDuration = TimeSpan.FromMinutes(30) };

        await limiter.CheckAsync(new RateLimitAttempt { Purpose = "login", Key = blockedKey }, rule);
        await limiter.CheckAsync(new RateLimitAttempt { Purpose = "login", Key = blockedKey }, rule);
        await limiter.CheckAsync(new RateLimitAttempt { Purpose = "login", Key = activeKey }, rule);
        await limiter.CheckAsync(new RateLimitAttempt { Purpose = "reset", Key = otherPurposeKey }, rule);

        var login = await administration.SearchBucketsAsync(new SearchAuthenticationRateLimitBucketsRequest { Purpose = "login" });
        var blocked = await administration.SearchBucketsAsync(new SearchAuthenticationRateLimitBucketsRequest
        {
            Purpose = "login",
            Status = AuthenticationRateLimitBucketStatus.Blocked
        });
        var active = await administration.SearchBucketsAsync(new SearchAuthenticationRateLimitBucketsRequest
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

    [Test]
    public async Task SearchBucketsAsyncAllowsUnscopedPurposeBrowse()
    {
        await using var scope = CreateAsyncScope();
        var limiter = GetAuthenticationRateLimiter(scope.ServiceProvider);
        var administration = scope.ServiceProvider.GetRequiredService<IAuthenticationRateLimitAdministrationService>();
        var rule = new RateLimitRule { PermitLimit = 5, Window = TimeSpan.FromMinutes(10) };

        await limiter.CheckAsync(new RateLimitAttempt { Purpose = "browse-one", Key = UniqueKey() }, rule);
        await limiter.CheckAsync(new RateLimitAttempt { Purpose = "browse-two", Key = UniqueKey() }, rule);

        var result = await administration.SearchBucketsAsync(new SearchAuthenticationRateLimitBucketsRequest { Limit = 10 });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value!.Items.Select(item => item.Purpose), Does.Contain("browse-one"));
            Assert.That(result.Value.Items.Select(item => item.Purpose), Does.Contain("browse-two"));
        }
    }

    [Test]
    public async Task SearchBucketsAsyncAppliesDateFiltersAndStablePaging()
    {
        await using var scope = CreateAsyncScope();
        var limiter = GetAuthenticationRateLimiter(scope.ServiceProvider);
        var administration = scope.ServiceProvider.GetRequiredService<IAuthenticationRateLimitAdministrationService>();
        var rule = new RateLimitRule { PermitLimit = 5, Window = TimeSpan.FromMinutes(10) };

        await limiter.CheckAsync(new RateLimitAttempt { Purpose = "paging", Key = UniqueKey() }, rule);
        AdvanceTime(TimeSpan.FromMinutes(1));
        var secondStart = Now;
        await limiter.CheckAsync(new RateLimitAttempt { Purpose = "paging", Key = UniqueKey() }, rule);
        await limiter.CheckAsync(new RateLimitAttempt { Purpose = "paging", Key = UniqueKey() }, rule);

        var filtered = await administration.SearchBucketsAsync(new SearchAuthenticationRateLimitBucketsRequest
        {
            Purpose = "paging",
            WindowStartFrom = secondStart,
            WindowStartTo = secondStart,
            ExpiresFrom = secondStart + rule.Window,
            ExpiresTo = secondStart + rule.Window,
            Limit = 1
        });
        var secondPage = await administration.SearchBucketsAsync(new SearchAuthenticationRateLimitBucketsRequest
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

    [Test]
    public async Task SearchBucketsAsyncFiltersExpiredBuckets()
    {
        await using var scope = CreateAsyncScope();
        var limiter = GetAuthenticationRateLimiter(scope.ServiceProvider);
        var administration = scope.ServiceProvider.GetRequiredService<IAuthenticationRateLimitAdministrationService>();
        var rule = new RateLimitRule { PermitLimit = 5, Window = TimeSpan.FromMinutes(1) };

        await limiter.CheckAsync(new RateLimitAttempt { Purpose = "expired", Key = UniqueKey() }, rule);
        AdvanceTime(TimeSpan.FromMinutes(2));

        var expired = await administration.SearchBucketsAsync(new SearchAuthenticationRateLimitBucketsRequest
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

    [Test]
    public async Task GetBucketAsyncReturnsSafeLookup()
    {
        await using var scope = CreateAsyncScope();
        var limiter = GetAuthenticationRateLimiter(scope.ServiceProvider);
        var administration = scope.ServiceProvider.GetRequiredService<IAuthenticationRateLimitAdministrationService>();
        var rawKey = $"raw-email-{Guid.NewGuid():N}@example.com";

        await limiter.CheckAsync(
            new RateLimitAttempt { Purpose = "detail", Key = rawKey },
            new RateLimitRule { PermitLimit = 5, Window = TimeSpan.FromMinutes(10) });

        var search = await administration.SearchBucketsAsync(new SearchAuthenticationRateLimitBucketsRequest { Purpose = "detail" });
        var summary = search.Value!.Items.Single();
        var lookup = await administration.GetBucketAsync(new AuthenticationRateLimitBucketLookupRequest(summary.BucketId, "detail"));
        var mismatch = await administration.GetBucketAsync(new AuthenticationRateLimitBucketLookupRequest("not-the-bucket", "detail"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(lookup.Succeeded, Is.True);
            Assert.That(lookup.Value!.BucketId, Is.EqualTo(summary.BucketId));
            Assert.That(lookup.Value.BucketId, Does.Not.Contain(rawKey));
            Assert.That(lookup.Value.Purpose, Is.EqualTo("detail"));
            Assert.That(mismatch.Succeeded, Is.False);
        }
    }

    [Test]
    public async Task ResetBucketAsyncDeletesExistingBucketAndReportsMissingBucket()
    {
        await using var scope = CreateAsyncScope();
        var limiter = GetAuthenticationRateLimiter(scope.ServiceProvider);
        var administration = scope.ServiceProvider.GetRequiredService<IAuthenticationRateLimitAdministrationService>();
        var rawKey = UniqueKey();

        await limiter.CheckAsync(
            new RateLimitAttempt { Purpose = "reset", Key = rawKey },
            new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(10) });
        var bucket = (await administration.SearchBucketsAsync(new SearchAuthenticationRateLimitBucketsRequest { Purpose = "reset" })).Value!.Items.Single();

        var reset = await administration.ResetBucketAsync(new ResetAuthenticationRateLimitBucketRequest(bucket.BucketId, "reset", new AuditContext(Guid.NewGuid())));
        var missing = await administration.ResetBucketAsync(new ResetAuthenticationRateLimitBucketRequest(bucket.BucketId, "reset", new AuditContext(Guid.NewGuid())));
        var afterReset = await administration.GetBucketAsync(new AuthenticationRateLimitBucketLookupRequest(bucket.BucketId, "reset"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(reset.Value!.Status, Is.EqualTo(AuthenticationRateLimitBucketResetStatus.Reset));
            Assert.That(missing.Value!.Status, Is.EqualTo(AuthenticationRateLimitBucketResetStatus.NotFound));
            Assert.That(afterReset.Succeeded, Is.False);
        }
    }

    [Test]
    public async Task SearchBucketsAsyncDoesNotExposeRawSensitiveInputs()
    {
        await using var scope = CreateAsyncScope();
        var limiter = GetAuthenticationRateLimiter(scope.ServiceProvider);
        var administration = scope.ServiceProvider.GetRequiredService<IAuthenticationRateLimitAdministrationService>();
        var sensitive = $"user-{Guid.NewGuid():N}@example.com";

        await limiter.CheckAsync(
            new RateLimitAttempt { Purpose = "safe", Key = sensitive },
            new RateLimitRule { PermitLimit = 5, Window = TimeSpan.FromMinutes(10) });

        var search = await administration.SearchBucketsAsync(new SearchAuthenticationRateLimitBucketsRequest { Purpose = "safe" });
        var bucket = search.Value!.Items.Single();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(bucket.BucketId, Does.Not.Contain(sensitive));
            Assert.That(bucket.BucketId, Does.Not.Contain("user-"));
            Assert.That(bucket.BucketId, Does.Not.Contain("@example.com"));
        }
    }

    private static string UniqueKey() => $"admin-contract-{Guid.NewGuid():N}";
}
