using Ashlar.Identity.RateLimiting;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Microsoft.Extensions.Options;

namespace Ashlar.Tests.Identity.RateLimiting;

internal sealed class AuthenticationFactorRateLimiterTests
{
    [Test]
    public async Task CheckAsyncEvaluatesSourceAndUserBuckets()
    {
        var inner = new RecordingRateLimiter(RateLimitDecision.Allow());
        var limiter = new AuthenticationFactorRateLimiter(inner);
        var userId = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        var provider = new AuthenticationProviderKey(ProviderType.Passkey, "Passkey");
        var context = new AuthenticationContext(TenantId: Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"), IpAddress: " 203.0.113.15 ", UserId: userId);

        var decision = await limiter.CheckAsync(context, provider);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(decision.IsAllowed, Is.True);
            Assert.That(inner.Attempts, Has.Count.EqualTo(2));
            Assert.That(inner.Attempts.All(attempt => attempt.Purpose == "factor-verification"), Is.True);
            Assert.That(inner.Attempts.All(attempt => attempt.UserId == userId.ToString("D")), Is.True);
            Assert.That(inner.Attempts.All(attempt => attempt.IpAddress == "203.0.113.15"), Is.True);
            Assert.That(inner.Rules, Has.All.Matches<RateLimitRule>(rule =>
                rule.PermitLimit == 5 &&
                rule.Window == TimeSpan.FromMinutes(5) &&
                rule.BlockDuration == TimeSpan.FromMinutes(5)));
        }
    }

    [Test]
    public async Task CheckAsyncStopsWhenSourceBucketIsBlocked()
    {
        var inner = new RecordingRateLimiter(new RateLimitDecision { Status = RateLimitStatus.Blocked, Remaining = 0, WindowResetAt = DateTimeOffset.UtcNow });
        var limiter = new AuthenticationFactorRateLimiter(inner);

        var decision = await limiter.CheckAsync(
            new AuthenticationContext(IpAddress: "203.0.113.16", UserId: Guid.NewGuid()),
            new AuthenticationProviderKey(ProviderType.Passkey, "Passkey"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(decision.IsAllowed, Is.False);
            Assert.That(inner.Attempts, Has.Count.EqualTo(1));
        }
    }

    [Test]
    public async Task CheckAsyncUsesSingleSourceBucketWhenUserIdIsMissing()
    {
        var inner = new RecordingRateLimiter(RateLimitDecision.Allow());
        var limiter = new AuthenticationFactorRateLimiter(inner);

        await limiter.CheckAsync(
            new AuthenticationContext(IpAddress: "203.0.113.17"),
            new AuthenticationProviderKey(ProviderType.Passkey, "Passkey"));

        Assert.That(inner.Attempts, Has.Count.EqualTo(1));
    }

    [Test]
    public async Task CheckAsyncUsesProviderOverrideAndCanBeDisabledOrExcluded()
    {
        var provider = new AuthenticationProviderKey(ProviderType.Passkey, "Passkey");
        var overrideRule = new RateLimitRule { PermitLimit = 2, Window = TimeSpan.FromMinutes(2) };
        var overrideOptions = new AuthenticationFactorRateLimitOptions();
        overrideOptions.ProviderRules.Add("passkey:passkey", overrideRule);
        var overrideInner = new RecordingRateLimiter(RateLimitDecision.Allow());
        var overrideLimiter = new AuthenticationFactorRateLimiter(overrideInner, Options.Create(overrideOptions));

        await overrideLimiter.CheckAsync(new AuthenticationContext(UserId: Guid.NewGuid()), provider);

        var disabledOptions = new AuthenticationFactorRateLimitOptions { Enabled = false };
        var disabledInner = new RecordingRateLimiter(RateLimitDecision.Allow());
        var disabledLimiter = new AuthenticationFactorRateLimiter(disabledInner, Options.Create(disabledOptions));

        await disabledLimiter.CheckAsync(new AuthenticationContext(UserId: Guid.NewGuid()), provider);

        var excludedOptions = new AuthenticationFactorRateLimitOptions();
        excludedOptions.ExcludedProviders.Add("passkey:passkey");
        var excludedInner = new RecordingRateLimiter(RateLimitDecision.Allow());
        var excludedLimiter = new AuthenticationFactorRateLimiter(excludedInner, Options.Create(excludedOptions));

        await excludedLimiter.CheckAsync(new AuthenticationContext(UserId: Guid.NewGuid()), provider);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(overrideInner.Rules, Has.All.EqualTo(overrideRule));
            Assert.That(disabledInner.Attempts, Is.Empty);
            Assert.That(excludedInner.Attempts, Is.Empty);
        }
    }

    [Test]
    public void OptionsValidationRejectsInvalidConfiguration()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(AuthenticationFactorRateLimitOptions.Validate(new AuthenticationFactorRateLimitOptions()), Is.True);
            Assert.That(AuthenticationFactorRateLimitOptions.Validate(null), Is.False);
            Assert.That(AuthenticationFactorRateLimitOptions.Validate(new AuthenticationFactorRateLimitOptions { DefaultRule = new RateLimitRule { PermitLimit = 0, Window = TimeSpan.FromMinutes(1) } }), Is.False);
        }

        var invalidProviderRule = new AuthenticationFactorRateLimitOptions();
        invalidProviderRule.ProviderRules.Add("passkey", new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(1) });
        var invalidExcludedProvider = new AuthenticationFactorRateLimitOptions();
        invalidExcludedProvider.ExcludedProviders.Add(" passkey:passkey ");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(AuthenticationFactorRateLimitOptions.Validate(invalidProviderRule), Is.False);
            Assert.That(AuthenticationFactorRateLimitOptions.Validate(invalidExcludedProvider), Is.False);
            Assert.Throws<OptionsValidationException>(() => _ = new AuthenticationFactorRateLimiter(new RecordingRateLimiter(RateLimitDecision.Allow()), Options.Create(invalidProviderRule)));
            Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationFactorRateLimiter(null!));
            Assert.ThrowsAsync<ArgumentNullException>(() => new AuthenticationFactorRateLimiter(new RecordingRateLimiter(RateLimitDecision.Allow())).CheckAsync(null!, AuthenticationProviderKey.Local));
        }
    }

    private sealed class RecordingRateLimiter(RateLimitDecision decision) : IAuthenticationRateLimiter
    {
        public List<RateLimitAttempt> Attempts { get; } = [];
        public List<RateLimitRule> Rules { get; } = [];

        public Task<RateLimitDecision> CheckAsync(RateLimitAttempt attempt, RateLimitRule rule, CancellationToken cancellationToken = default)
        {
            lock (Attempts)
            {
                Attempts.Add(attempt);
                Rules.Add(rule);
            }

            return Task.FromResult(decision);
        }
    }
}
