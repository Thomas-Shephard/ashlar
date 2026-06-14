using Ashlar.Identity.Providers.Local;
using Ashlar.Identity.RateLimiting;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Microsoft.Extensions.Options;

namespace Ashlar.Tests.Identity.RateLimiting;

internal sealed class PrimaryAuthenticationRateLimiterTests
{
    [Test]
    public async Task CheckAsyncWithAllowedPrimaryAttemptEvaluatesAllLayers()
    {
        var inner = new RecordingAuthenticationRateLimiter();
        var limiter = new PrimaryAuthenticationRateLimiter(inner);
        var context = new AuthenticationContext(" Test@Example.COM ", TenantId: Guid.NewGuid(), IpAddress: "203.0.113.10");

        var decision = await limiter.CheckAsync(context, new LocalPasswordAssertion("password"), AuthenticationProviderKey.Local);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(decision.IsAllowed, Is.True);
            Assert.That(inner.Attempts, Has.Count.EqualTo(2));
            Assert.That(inner.Attempts.Select(a => a.Purpose), Is.All.EqualTo("primary-authentication"));
            Assert.That(inner.Attempts.Select(a => a.Email), Is.All.EqualTo("TEST@EXAMPLE.COM"));
            Assert.That(inner.Attempts.Select(a => a.IpAddress), Is.All.EqualTo("203.0.113.10"));
            Assert.That(inner.Attempts.Select(a => a.Key), Is.All.Matches<string>(key => key.Length == 64));
            Assert.That(string.Join("|", inner.Attempts.Select(a => a.Key)), Does.Not.Contain("password"));
            Assert.That(inner.Rules, Has.All.Matches<RateLimitRule>(rule =>
                rule.PermitLimit == 5 &&
                rule.Window == TimeSpan.FromMinutes(10) &&
                rule.BlockDuration == TimeSpan.FromMinutes(10)));
        }
    }

    [Test]
    public async Task CheckAsyncReturnsBlockedWhenAnyLayerBlocks()
    {
        var blocked = new RateLimitDecision
        {
            Status = RateLimitStatus.Blocked,
            Remaining = 0,
            WindowResetAt = DateTimeOffset.UtcNow.AddMinutes(1),
            RetryAfter = DateTimeOffset.UtcNow.AddMinutes(1)
        };
        var inner = new RecordingAuthenticationRateLimiter(blocked, RateLimitDecision.Allow(), RateLimitDecision.Allow());
        var limiter = new PrimaryAuthenticationRateLimiter(inner);

        var decision = await limiter.CheckAsync(new AuthenticationContext("test@example.com", IpAddress: "203.0.113.10"), new LocalPasswordAssertion("password"), AuthenticationProviderKey.Local);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(decision, Is.SameAs(blocked));
            Assert.That(inner.Attempts, Has.Count.EqualTo(1));
        }
    }

    [Test]
    public async Task CheckAsyncWithDisabledOptionsSkipsInnerLimiter()
    {
        var inner = new RecordingAuthenticationRateLimiter();
        var limiter = new PrimaryAuthenticationRateLimiter(
            inner,
            Options.Create(new PrimaryAuthenticationRateLimitOptions { Enabled = false }));

        var decision = await limiter.CheckAsync(new AuthenticationContext(), new LocalPasswordAssertion("password"), AuthenticationProviderKey.Local);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(decision.IsAllowed, Is.True);
            Assert.That(inner.Attempts, Is.Empty);
        }
    }

    [Test]
    public async Task CheckAsyncWithExcludedProviderSkipsInnerLimiter()
    {
        var options = new PrimaryAuthenticationRateLimitOptions();
        options.ExcludedProviders.Add("LOCAL:LOCAL");
        var inner = new RecordingAuthenticationRateLimiter();
        var limiter = new PrimaryAuthenticationRateLimiter(inner, Options.Create(options));

        var decision = await limiter.CheckAsync(new AuthenticationContext(), new LocalPasswordAssertion("password"), AuthenticationProviderKey.Local);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(decision.IsAllowed, Is.True);
            Assert.That(inner.Attempts, Is.Empty);
        }
    }

    [Test]
    public async Task CheckAsyncUsesProviderSpecificRule()
    {
        var options = new PrimaryAuthenticationRateLimitOptions();
        options.ProviderRules["LOCAL:LOCAL"] = new RateLimitRule
        {
            PermitLimit = 2,
            Window = TimeSpan.FromMinutes(3),
            BlockDuration = TimeSpan.FromMinutes(4)
        };
        var inner = new RecordingAuthenticationRateLimiter();
        var limiter = new PrimaryAuthenticationRateLimiter(inner, Options.Create(options));

        await limiter.CheckAsync(new AuthenticationContext(Email: "test@example.com"), new LocalPasswordAssertion("password"), AuthenticationProviderKey.Local);

        Assert.That(inner.Rules, Has.All.Matches<RateLimitRule>(rule =>
            rule.PermitLimit == 2 &&
            rule.Window == TimeSpan.FromMinutes(3) &&
            rule.BlockDuration == TimeSpan.FromMinutes(4)));
    }

    [Test]
    public void ConstructorRejectsNullDependenciesAndInvalidOptions()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new PrimaryAuthenticationRateLimiter(null!));
            Assert.Throws<OptionsValidationException>(() => _ = new PrimaryAuthenticationRateLimiter(
                new RecordingAuthenticationRateLimiter(),
                Options.Create(new PrimaryAuthenticationRateLimitOptions
                {
                    DefaultRule = new RateLimitRule { PermitLimit = 0, Window = TimeSpan.FromMinutes(1) }
                })));
        }
    }

    [Test]
    public void CheckAsyncRejectsNullArguments()
    {
        var limiter = new PrimaryAuthenticationRateLimiter(new RecordingAuthenticationRateLimiter());

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentNullException>(() => limiter.CheckAsync(null!, new LocalPasswordAssertion("password"), AuthenticationProviderKey.Local));
            Assert.ThrowsAsync<ArgumentNullException>(() => limiter.CheckAsync(new AuthenticationContext(), null!, AuthenticationProviderKey.Local));
        }
    }

    [Test]
    public void OptionsValidationCoversInvalidShapes()
    {
        var valid = new PrimaryAuthenticationRateLimitOptions();
        valid.ProviderRules["local:local"] = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromSeconds(1) };
        valid.ExcludedProviders.Add("oidc:contoso");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(PrimaryAuthenticationRateLimitOptions.Validate(valid), Is.True);
            Assert.That(new PrimaryAuthenticationRateLimitOptions().FailOpenOnBackendFailure, Is.False);
            Assert.That(PrimaryAuthenticationRateLimitOptions.Validate(null), Is.False);
            Assert.That(PrimaryAuthenticationRateLimitOptions.Validate(new PrimaryAuthenticationRateLimitOptions
            {
                DefaultRule = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.Zero }
            }), Is.False);
            Assert.That(PrimaryAuthenticationRateLimitOptions.Validate(new PrimaryAuthenticationRateLimitOptions
            {
                DefaultRule = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromSeconds(1), BlockDuration = TimeSpan.Zero }
            }), Is.False);
        }

        var invalidProviderRule = new PrimaryAuthenticationRateLimitOptions();
        invalidProviderRule.ProviderRules["bad"] = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromSeconds(1) };
        var invalidProviderRuleValue = new PrimaryAuthenticationRateLimitOptions();
        invalidProviderRuleValue.ProviderRules["local:local"] = new RateLimitRule { PermitLimit = 0, Window = TimeSpan.FromSeconds(1) };
        var invalidExclusion = new PrimaryAuthenticationRateLimitOptions();
        invalidExclusion.ExcludedProviders.Add("local:");
        var blankExclusion = new PrimaryAuthenticationRateLimitOptions();
        blankExclusion.ExcludedProviders.Add(" ");
        var paddedExclusion = new PrimaryAuthenticationRateLimitOptions();
        paddedExclusion.ExcludedProviders.Add(" local:local ");
        var emptyTypeExclusion = new PrimaryAuthenticationRateLimitOptions();
        emptyTypeExclusion.ExcludedProviders.Add(" :local");
        var emptyNameExclusion = new PrimaryAuthenticationRateLimitOptions();
        emptyNameExclusion.ExcludedProviders.Add("local: ");
        var paddedTypeExclusion = new PrimaryAuthenticationRateLimitOptions();
        paddedTypeExclusion.ExcludedProviders.Add("local :local");
        var paddedNameExclusion = new PrimaryAuthenticationRateLimitOptions();
        paddedNameExclusion.ExcludedProviders.Add("local: local");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(PrimaryAuthenticationRateLimitOptions.Validate(invalidProviderRule), Is.False);
            Assert.That(PrimaryAuthenticationRateLimitOptions.Validate(invalidProviderRuleValue), Is.False);
            Assert.That(PrimaryAuthenticationRateLimitOptions.Validate(invalidExclusion), Is.False);
            Assert.That(PrimaryAuthenticationRateLimitOptions.Validate(blankExclusion), Is.False);
            Assert.That(PrimaryAuthenticationRateLimitOptions.Validate(paddedExclusion), Is.False);
            Assert.That(PrimaryAuthenticationRateLimitOptions.Validate(emptyTypeExclusion), Is.False);
            Assert.That(PrimaryAuthenticationRateLimitOptions.Validate(emptyNameExclusion), Is.False);
            Assert.That(PrimaryAuthenticationRateLimitOptions.Validate(paddedTypeExclusion), Is.False);
            Assert.That(PrimaryAuthenticationRateLimitOptions.Validate(paddedNameExclusion), Is.False);
        }
    }

    private sealed class RecordingAuthenticationRateLimiter(params RateLimitDecision[] decisions) : IAuthenticationRateLimiter
    {
        private readonly Queue<RateLimitDecision> _decisions = new(decisions);

        public List<RateLimitAttempt> Attempts { get; } = [];

        public List<RateLimitRule> Rules { get; } = [];

        public Task<RateLimitDecision> CheckAsync(RateLimitAttempt attempt, RateLimitRule rule, CancellationToken cancellationToken = default)
        {
            lock (_decisions)
            {
                Attempts.Add(attempt);
                Rules.Add(rule);
                return Task.FromResult(_decisions.Count == 0 ? RateLimitDecision.Allow() : _decisions.Dequeue());
            }
        }
    }
}
