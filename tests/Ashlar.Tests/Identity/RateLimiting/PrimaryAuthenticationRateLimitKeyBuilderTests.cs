using Ashlar.Identity.Providers.Local;
using Ashlar.Identity.Providers.External;
using Ashlar.Identity.RateLimiting;

namespace Ashlar.Tests.Identity.RateLimiting;

internal sealed class PrimaryAuthenticationRateLimitKeyBuilderTests
{
    [Test]
    public void SameEmailWithDifferentCasingAndSpacingMapsToSameBucket()
    {
        var first = Build(new AuthenticationContext(" Test@Example.COM ", IpAddress: "203.0.113.1"));
        var second = Build(new AuthenticationContext("test@example.com", IpAddress: "203.0.113.1"));

        Assert.That(first, Is.EqualTo(second));
    }

    [Test]
    public void TenantAndProviderArePartOfTheBucket()
    {
        var tenantA = Build(new AuthenticationContext("test@example.com", TenantId: Guid.NewGuid(), IpAddress: "203.0.113.1"));
        var tenantB = Build(new AuthenticationContext("test@example.com", TenantId: Guid.NewGuid(), IpAddress: "203.0.113.1"));
        var providerB = PrimaryAuthenticationRateLimitKeyBuilder.BuildAttempts(
            new AuthenticationContext("test@example.com", IpAddress: "203.0.113.1"),
            new TestAssertion(new AuthenticationProviderKey(ProviderType.Oidc, "Contoso")),
            new AuthenticationProviderKey(ProviderType.Oidc, "Contoso")).Select(a => a.Key).ToArray();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(tenantA, Is.Not.EqualTo(tenantB));
            Assert.That(Build(new AuthenticationContext("test@example.com", IpAddress: "203.0.113.1")), Is.Not.EqualTo(providerB));
        }
    }

    [Test]
    public void UserIdContextMapsToStableUserBucket()
    {
        var userId = Guid.NewGuid();
        var first = Build(new AuthenticationContext(UserId: userId, IpAddress: "203.0.113.1"));
        var second = Build(new AuthenticationContext(UserId: userId, IpAddress: "203.0.113.1"));

        Assert.That(first, Is.EqualTo(second));
    }

    [Test]
    public void SourceFallbackWorksWithoutEmailOrUserId()
    {
        var ip = Build(new AuthenticationContext(IpAddress: "203.0.113.55"));
        var correlationOnly = Build(new AuthenticationContext(CorrelationId: "corr-1"));
        var anonymous = Build(new AuthenticationContext());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(ip, Has.Length.EqualTo(1));
            Assert.That(correlationOnly, Has.Length.EqualTo(1));
            Assert.That(anonymous, Has.Length.EqualTo(1));
            Assert.That(ip, Is.Not.EqualTo(anonymous));
            Assert.That(correlationOnly, Is.EqualTo(anonymous));
        }
    }

    [Test]
    public void IdentityDimensionKeepsLayeredBucketsWhenIdentityIsKnown()
    {
        var attempts = PrimaryAuthenticationRateLimitKeyBuilder.BuildAttempts(
            new AuthenticationContext("test@example.com", IpAddress: "203.0.113.1"),
            new LocalPasswordAssertion("password"),
            AuthenticationProviderKey.Local);

        Assert.That(attempts, Has.Count.EqualTo(2));
    }

    [Test]
    public void CredentialKeyCanBeUsedWithoutBeingStoredRaw()
    {
        var attempts = PrimaryAuthenticationRateLimitKeyBuilder.BuildAttempts(
            new AuthenticationContext(IpAddress: "203.0.113.1"),
            new CredentialKeyAssertion(AuthenticationProviderKey.Passkey, "credential-secret"),
            AuthenticationProviderKey.Passkey);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(attempts.Select(a => a.Key), Is.All.Not.Contains("credential-secret"));
            Assert.That(attempts.Select(a => a.Email), Is.All.Null);
            Assert.That(attempts.Select(a => a.UserId), Is.All.Null);
        }
    }

    [Test]
    public void ExternalProviderKeyContributesCredentialBucketWithoutBeingStoredRaw()
    {
        var first = PrimaryAuthenticationRateLimitKeyBuilder.BuildAttempts(
            new AuthenticationContext(IpAddress: "203.0.113.1"),
            new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "external-user-1", new Dictionary<string, string>()),
            new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        var second = PrimaryAuthenticationRateLimitKeyBuilder.BuildAttempts(
            new AuthenticationContext(IpAddress: "203.0.113.1"),
            new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "external-user-2", new Dictionary<string, string>()),
            new AuthenticationProviderKey(ProviderType.Oidc, "Google"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(first.Select(a => a.Key), Is.Not.EqualTo(second.Select(a => a.Key)));
            Assert.That(string.Join("|", first.Select(a => a.Key)), Does.Not.Contain("external-user-1"));
            Assert.That(string.Join("|", second.Select(a => a.Key)), Does.Not.Contain("external-user-2"));
        }
    }

    [Test]
    public void PasswordNeverAppearsInGeneratedKeys()
    {
        var attempts = PrimaryAuthenticationRateLimitKeyBuilder.BuildAttempts(
            new AuthenticationContext("test@example.com", IpAddress: "203.0.113.1"),
            new LocalPasswordAssertion("correct horse battery staple"),
            AuthenticationProviderKey.Local);

        Assert.That(string.Join("|", attempts.Select(a => a.Key)), Does.Not.Contain("correct horse battery staple"));
    }

    [Test]
    public void BuildAttemptsRejectsNullArguments()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => PrimaryAuthenticationRateLimitKeyBuilder.BuildAttempts(null!, new LocalPasswordAssertion("password"), AuthenticationProviderKey.Local));
            Assert.Throws<ArgumentNullException>(() => PrimaryAuthenticationRateLimitKeyBuilder.BuildAttempts(new AuthenticationContext(), null!, AuthenticationProviderKey.Local));
        }
    }

    [Test]
    public void ProviderSelectorNormalizesNameAndUnknownType()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(PrimaryAuthenticationRateLimitKeyBuilder.NormalizeProviderSelector(new AuthenticationProviderKey(ProviderType.Local, " LOCAL ")), Is.EqualTo("local:local"));
            Assert.That(PrimaryAuthenticationRateLimitKeyBuilder.NormalizeProviderSelector(default), Is.EqualTo("unknown:"));
        }
    }

    private static string[] Build(AuthenticationContext context)
    {
        return PrimaryAuthenticationRateLimitKeyBuilder.BuildAttempts(context, new LocalPasswordAssertion("password"), AuthenticationProviderKey.Local)
            .Select(a => a.Key)
            .ToArray();
    }

    private sealed record TestAssertion(AuthenticationProviderKey ProviderIdentity) : IAuthenticationAssertion;

    private sealed record CredentialKeyAssertion(AuthenticationProviderKey ProviderIdentity, string CredentialKey) : ICredentialKeyAuthenticationAssertion;
}
