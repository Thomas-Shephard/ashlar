using Ashlar.Identity.RateLimiting;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.Tests.Identity.RateLimiting;

internal sealed class AuthenticationRateLimitCheckerTests
{
    [Test]
    public async Task CheckAsyncBuildsHashedAttemptWithSafeMetadata()
    {
        var inner = new RecordingRateLimiter(RateLimitDecision.Allow());
        var checker = new AuthenticationRateLimitChecker(inner);
        var tenantId = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        var userId = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
        var context = new AuthenticationContext(
            TenantId: tenantId,
            IpAddress: " 203.0.113.10 ",
            UserAgent: null,
            CorrelationId: " corr ",
            Items: null,
            Email: " Context@Example.Com ",
            UserId: userId);

        await checker.CheckAsync(new AuthenticationRateLimitCheck(
            "test-purpose",
            "Email",
            " User@Example.Com ",
            ValidRule())
        {
            ProviderKey = new AuthenticationProviderKey(ProviderType.Local, "LOCAL"),
            Context = context,
            Email = " Override@Example.Com ",
            UserId = Guid.Parse("cccccccc-cccc-cccc-cccc-cccccccccccc")
        });

        var attempt = inner.Attempts.Single();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(attempt.Key, Is.EqualTo(AuthenticationRateLimitKeyBuilder.HashKey("12:test-purpose|11:local:local|36:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa|5:email|16:User@Example.Com")));
            Assert.That(attempt.Purpose, Is.EqualTo("test-purpose"));
            Assert.That(attempt.Email, Is.EqualTo("OVERRIDE@EXAMPLE.COM"));
            Assert.That(attempt.UserId, Is.EqualTo("cccccccc-cccc-cccc-cccc-cccccccccccc"));
            Assert.That(attempt.IpAddress, Is.EqualTo("203.0.113.10"));
            Assert.That(attempt.CorrelationId, Is.EqualTo("corr"));
        }
    }

    [Test]
    public async Task CheckAsyncUsesGlobalBucketWithoutProviderOrContext()
    {
        var inner = new RecordingRateLimiter(RateLimitDecision.Allow());
        var checker = new AuthenticationRateLimitChecker(inner);

        await checker.CheckAsync(new AuthenticationRateLimitCheck("purpose", "source", "anonymous", ValidRule()));

        Assert.That(inner.Attempts.Single().Key, Is.EqualTo(AuthenticationRateLimitKeyBuilder.HashKey("7:purpose|4:none|6:global|6:source|9:anonymous")));
    }

    [Test]
    public async Task CheckAsyncTrimsNonIpSourceMetadata()
    {
        var inner = new RecordingRateLimiter(RateLimitDecision.Allow());
        var checker = new AuthenticationRateLimitChecker(inner);

        await checker.CheckAsync(new AuthenticationRateLimitCheck("purpose", "source", "anonymous", ValidRule())
        {
            Context = new AuthenticationContext(IpAddress: " not-an-ip ")
        });

        Assert.That(inner.Attempts.Single().IpAddress, Is.EqualTo("not-an-ip"));
    }

    [Test]
    public void BuildAttemptUsesUnambiguousSegmentEncodingBeforeHashing()
    {
        var first = AuthenticationRateLimitKeyBuilder.BuildAttempt("purpose", "source", "a|b");
        var second = AuthenticationRateLimitKeyBuilder.BuildAttempt("purpose", "source|a", "b");

        Assert.That(first.Key, Is.Not.EqualTo(second.Key));
    }

    [Test]
    public void CheckAsyncRejectsInvalidInputs()
    {
        var checker = new AuthenticationRateLimitChecker(new RecordingRateLimiter(RateLimitDecision.Allow()));

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationRateLimitChecker(null!));
            Assert.ThrowsAsync<ArgumentNullException>(() => checker.CheckAsync(null!));
            Assert.ThrowsAsync<ArgumentException>(() => checker.CheckAsync(new AuthenticationRateLimitCheck(" ", "source", "value", ValidRule())));
            Assert.ThrowsAsync<ArgumentException>(() => checker.CheckAsync(new AuthenticationRateLimitCheck("purpose", " ", "value", ValidRule())));
            Assert.ThrowsAsync<ArgumentException>(() => checker.CheckAsync(new AuthenticationRateLimitCheck("purpose", "source", " ", ValidRule())));
            Assert.ThrowsAsync<ArgumentException>(() => checker.CheckAsync(new AuthenticationRateLimitCheck("purpose", "source", "value", new RateLimitRule { PermitLimit = 0, Window = TimeSpan.FromMinutes(1) })));
            Assert.Throws<ArgumentNullException>(() => AuthenticationRateLimitKeyBuilder.HashKey(null!));
        }
    }

    [Test]
    public void RuleValidatorHandlesAllRuleShapes()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(AuthenticationRateLimitRuleValidator.IsValid(null), Is.False);
            Assert.That(AuthenticationRateLimitRuleValidator.IsValid(new RateLimitRule { PermitLimit = 0, Window = TimeSpan.FromMinutes(1) }), Is.False);
            Assert.That(AuthenticationRateLimitRuleValidator.IsValid(new RateLimitRule { PermitLimit = 1, Window = TimeSpan.Zero }), Is.False);
            Assert.That(AuthenticationRateLimitRuleValidator.IsValid(new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(1), BlockDuration = TimeSpan.Zero }), Is.False);
            Assert.That(AuthenticationRateLimitRuleValidator.IsValid(new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(1), BlockDuration = TimeSpan.FromMinutes(1) }), Is.True);
        }
    }

    [Test]
    public void DimensionsBuildCommonBucketKeysAndNames()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(AuthenticationRateLimitDimensions.Email("user@example.com"), Is.EqualTo("email:user@example.com"));
            Assert.That(AuthenticationRateLimitDimensions.TokenHash("safe-hash"), Is.EqualTo("token:safe-hash"));
            Assert.That(AuthenticationRateLimitDimensions.Source(new AuthenticationContext(IpAddress: "203.0.113.10")), Is.EqualTo("source:ip:203.0.113.10"));
            Assert.That(AuthenticationRateLimitDimensions.Source(new AuthenticationContext(IpAddress: " 203.0.113.10 ")), Is.EqualTo("source:ip:203.0.113.10"));
            Assert.That(AuthenticationRateLimitDimensions.Source(new AuthenticationContext(IpAddress: "2001:0db8:0000:0000:0000:ff00:0042:8329")), Is.EqualTo("source:ip:2001:db8::ff00:42:8329"));
            Assert.That(AuthenticationRateLimitDimensions.Source(new AuthenticationContext(IpAddress: " not-an-ip ")), Is.EqualTo("source:ip:not-an-ip"));
            Assert.That(AuthenticationRateLimitDimensions.Source(null), Is.EqualTo("source:anonymous"));
            Assert.That(AuthenticationRateLimitDimensions.Source(new AuthenticationContext(IpAddress: " ")), Is.EqualTo("source:anonymous"));
            Assert.That(AuthenticationRateLimitDimensions.User(Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")), Is.EqualTo("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"));
            Assert.That(AuthenticationRateLimitDimensions.DimensionName("email:user@example.com"), Is.EqualTo("email"));
            Assert.That(AuthenticationRateLimitDimensions.DimensionName("token:safe-hash"), Is.EqualTo("token-hash"));
            Assert.That(AuthenticationRateLimitDimensions.DimensionName("source:ip:203.0.113.10"), Is.EqualTo("source"));
            Assert.That(AuthenticationRateLimitDimensions.DimensionName("source:anonymous"), Is.EqualTo("source"));
            Assert.That(AuthenticationRateLimitDimensions.DimensionName("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), Is.EqualTo("user"));
            Assert.Throws<ArgumentException>(() => AuthenticationRateLimitDimensions.Email(" "));
            Assert.Throws<ArgumentException>(() => AuthenticationRateLimitDimensions.TokenHash(" "));
            Assert.Throws<ArgumentException>(() => AuthenticationRateLimitDimensions.DimensionName(" "));
        }
    }

    private static RateLimitRule ValidRule()
    {
        return new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(1) };
    }

    private sealed class RecordingRateLimiter(RateLimitDecision decision) : IAuthenticationRateLimiter
    {
        public List<RateLimitAttempt> Attempts { get; } = [];

        public Task<RateLimitDecision> CheckAsync(RateLimitAttempt attempt, RateLimitRule rule, CancellationToken cancellationToken = default)
        {
            Attempts.Add(attempt);
            return Task.FromResult(decision);
        }
    }
}
