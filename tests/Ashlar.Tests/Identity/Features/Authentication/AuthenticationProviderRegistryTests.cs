using Ashlar.Identity.Providers.External;
using Moq;

namespace Ashlar.Tests.Identity.Features.Authentication;

internal sealed class AuthenticationProviderRegistryTests
{
    [Test]
    public void TryGetProviderWithSupportedAssertionShouldReturnRegisteredProvider()
    {
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = CreateProvider(AuthenticationProviderKey.Local);
        var registry = new AuthenticationProviderRegistry([provider.Object]);

        var found = registry.TryGetProvider(assertion, out var resolvedProvider);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(found, Is.True);
            Assert.That(resolvedProvider, Is.SameAs(provider.Object));
        }
    }

    [Test]
    public void TryGetProviderWithUnsupportedAssertionShouldReturnFalse()
    {
        var registry = new AuthenticationProviderRegistry([CreateProvider(AuthenticationProviderKey.Local).Object]);

        var found = registry.TryGetProvider(new TestAssertion(new AuthenticationProviderKey(ProviderType.Oidc, ProviderType.Oidc.Value)), out _);

        Assert.That(found, Is.False);
    }

    [Test]
    public void TryGetProviderWithProviderKeyShouldReturnRegisteredProvider()
    {
        var provider = CreateProvider(AuthenticationProviderKey.Local);
        var registry = new AuthenticationProviderRegistry([provider.Object]);

        var found = registry.TryGetProvider(AuthenticationProviderKey.Local, out var resolvedProvider);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(found, Is.True);
            Assert.That(resolvedProvider, Is.SameAs(provider.Object));
        }
    }

    [Test]
    public void ConstructorWithDuplicateProviderKeyShouldThrow()
    {
        Assert.Throws<ArgumentException>(() => _ = new AuthenticationProviderRegistry(
        [
            CreateProvider(new AuthenticationProviderKey(ProviderType.Oidc, "Google")).Object,
            CreateProvider(new AuthenticationProviderKey(ProviderType.Oidc, "Google")).Object
        ]));
    }

    [Test]
    public void ConstructorWithSameTypeAndDifferentNamesShouldRegisterBothProviders()
    {
        var google = CreateProvider(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        var microsoft = CreateProvider(new AuthenticationProviderKey(ProviderType.Oidc, "Microsoft"));
        var registry = new AuthenticationProviderRegistry([google.Object, microsoft.Object]);

        var keys = registry.SupportedProviderKeys.ToList();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(keys, Has.Count.EqualTo(2));
            Assert.That(keys, Does.Contain(new AuthenticationProviderKey(ProviderType.Oidc, "Google")));
            Assert.That(keys, Does.Contain(new AuthenticationProviderKey(ProviderType.Oidc, "Microsoft")));
        }
    }

    [Test]
    public void ConstructorWithDuplicateProviderNamesDifferingByCaseAndWhitespaceShouldThrow()
    {
        Assert.Throws<ArgumentException>(() => _ = new AuthenticationProviderRegistry(
        [
            CreateProvider(new AuthenticationProviderKey(ProviderType.Oidc, "Google")).Object,
            CreateProvider(new AuthenticationProviderKey(ProviderType.Oidc, " google ")).Object
        ]));
    }

    [Test]
    public void TryGetProviderWithExternalProviderNameShouldResolveMatchingProvider()
    {
        var google = CreateProvider(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        var microsoft = CreateProvider(new AuthenticationProviderKey(ProviderType.Oidc, "Microsoft"));
        var registry = new AuthenticationProviderRegistry([google.Object, microsoft.Object]);

        var googleFound = registry.TryGetProvider(new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "sub", new Dictionary<string, string>()), out var googleProvider);
        var microsoftFound = registry.TryGetProvider(new ExternalIdentityAssertion(ProviderType.Oidc, "Microsoft", "sub", new Dictionary<string, string>()), out var microsoftProvider);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(googleFound, Is.True);
            Assert.That(googleProvider, Is.SameAs(google.Object));
            Assert.That(microsoftFound, Is.True);
            Assert.That(microsoftProvider, Is.SameAs(microsoft.Object));
        }
    }

    [Test]
    public void TryGetProviderWithUnsupportedExternalProviderNameShouldReturnFalse()
    {
        var registry = new AuthenticationProviderRegistry([CreateProvider(new AuthenticationProviderKey(ProviderType.Oidc, "Google")).Object]);

        var found = registry.TryGetProvider(new ExternalIdentityAssertion(ProviderType.Oidc, "Okta", "sub", new Dictionary<string, string>()), out _);

        Assert.That(found, Is.False);
    }

    [Test]
    public void ConstructorWithNullProviderShouldThrowArgumentNullException()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationProviderRegistry([null!]));
    }

    [Test]
    public void ConstructorWithNullProvidersCollectionShouldThrowArgumentNullException()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationProviderRegistry(null!));
    }

    [Test]
    public void ConstructorWithProviderHavingDefaultKeyShouldThrow()
    {
        var provider = new Mock<IAuthenticationProvider>();
        provider.SetupGet(p => p.Key).Returns(default(AuthenticationProviderKey));

        var ex = Assert.Throws<ArgumentException>(() => _ = new AuthenticationProviderRegistry([provider.Object]));
        Assert.That(ex.Message, Does.Contain("fully initialized"));
    }

    [Test]
    public void ConstructorWithProviderHavingStorageFallbackKeyShouldThrow()
    {
        var provider = new Mock<IAuthenticationProvider>();
        provider.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey((ProviderType)ProviderType.StorageFallbackValue, "unknown"));

        var ex = Assert.Throws<ArgumentException>(() => _ = new AuthenticationProviderRegistry([provider.Object]));
        Assert.That(ex.Message, Does.Contain("fully initialized"));
    }

    [Test]
    public void ConstructorWithSecondaryProviderHavingBlankFactorTypeShouldThrow()
    {
        var provider = new Mock<ISecondaryAuthenticationFactorProvider>();
        provider.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Mfa, "custom"));
        provider.SetupGet(p => p.FactorType).Returns(" ");

        var ex = Assert.Throws<ArgumentException>(() => _ = new AuthenticationProviderRegistry([provider.Object]));
        Assert.That(ex.Message, Does.Contain("factor type"));
    }

    [Test]
    public void ProviderCapabilitiesClassifyProviderInstances()
    {
        var genericProvider = CreateProvider(new AuthenticationProviderKey("Custom", "Generic"));
        var primaryProvider = new Mock<IPrimaryAuthenticationProvider>();
        var secondaryProvider = new Mock<ISecondaryAuthenticationFactorProvider>();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(AuthenticationProviderCapabilities.IsPrimary(primaryProvider.Object), Is.True);
            Assert.That(AuthenticationProviderCapabilities.IsPrimary(genericProvider.Object), Is.False);
            Assert.That(AuthenticationProviderCapabilities.IsSecondaryFactor(secondaryProvider.Object), Is.True);
            Assert.That(AuthenticationProviderCapabilities.IsSecondaryFactor(genericProvider.Object), Is.False);
            Assert.Throws<ArgumentNullException>(() => AuthenticationProviderCapabilities.IsPrimary(null!));
            Assert.Throws<ArgumentNullException>(() => AuthenticationProviderCapabilities.IsSecondaryFactor(null!));
        }
    }

    private static Mock<IAuthenticationProvider> CreateProvider(AuthenticationProviderKey key)
    {
        var provider = new Mock<IAuthenticationProvider>();
        provider.SetupGet(p => p.Key).Returns(key);
        return provider;
    }

    private sealed record TestAssertion(AuthenticationProviderKey ProviderIdentity) : IAuthenticationAssertion;
}
