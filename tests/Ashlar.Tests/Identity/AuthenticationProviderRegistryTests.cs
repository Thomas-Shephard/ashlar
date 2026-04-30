using Ashlar.Identity;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Moq;

namespace Ashlar.Tests.Identity;

public class AuthenticationProviderRegistryTests
{
    [Test]
    public void TryGetProviderWithSupportedAssertionShouldReturnRegisteredProvider()
    {
        var assertion = new TestAssertion(ProviderType.Local);
        var provider = CreateProvider(ProviderType.Local);
        var registry = new AuthenticationProviderRegistry([provider.Object]);

        var found = registry.TryGetProvider(assertion, new AuthenticationContext("test@example.com"), out var resolvedProvider);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(found, Is.True);
            Assert.That(resolvedProvider, Is.SameAs(provider.Object));
        }
    }

    [Test]
    public void TryGetProviderWithUnsupportedAssertionShouldReturnFalse()
    {
        var registry = new AuthenticationProviderRegistry([CreateProvider(ProviderType.Local).Object]);

        var found = registry.TryGetProvider(new TestAssertion(ProviderType.Oidc), new AuthenticationContext(), out _);

        Assert.That(found, Is.False);
    }

    [Test]
    public void ConstructorWithDuplicateProviderTypeShouldThrow()
    {
        Assert.Throws<ArgumentException>(() => _ = new AuthenticationProviderRegistry(
        [
            CreateProvider(ProviderType.Local).Object,
            CreateProvider(ProviderType.Local).Object
        ]));
    }

    [Test]
    public void ConstructorWithNullProviderShouldThrowArgumentNullException()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationProviderRegistry([null!]));
    }

    private static Mock<IAuthenticationProvider> CreateProvider(ProviderType providerType)
    {
        var provider = new Mock<IAuthenticationProvider>();
        provider.SetupGet(p => p.SupportedType).Returns(providerType);
        return provider;
    }

    private sealed record TestAssertion(ProviderType ProviderType) : IAuthenticationAssertion;
}
