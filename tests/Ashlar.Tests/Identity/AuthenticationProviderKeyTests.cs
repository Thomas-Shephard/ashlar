using Ashlar.Identity.Models;

namespace Ashlar.Tests.Identity;

internal sealed class AuthenticationProviderKeyTests
{
    [Test]
    public void ConstructorShouldTrimProviderName()
    {
        var key = new AuthenticationProviderKey(ProviderType.Oidc, " Google ");

        Assert.That(key.Name, Is.EqualTo("Google"));
    }

    [Test]
    public void ConstructorShouldRejectNullOrWhiteSpaceProviderName()
    {
        using (Assert.EnterMultipleScope())
        {
            // ReSharper disable once NullableWarningSuppressionIsUsed
            Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationProviderKey(ProviderType.Oidc, null!));
            Assert.Throws<ArgumentException>(() => _ = new AuthenticationProviderKey(ProviderType.Oidc, ""));
            Assert.Throws<ArgumentException>(() => _ = new AuthenticationProviderKey(ProviderType.Oidc, " "));
        }
    }

    [Test]
    public void ConstructorShouldRejectDefaultProviderType()
    {
        Assert.Throws<ArgumentException>(() => _ = new AuthenticationProviderKey(default, "Google"));
    }

    [Test]
    public void EqualityShouldIgnoreProviderNameCase()
    {
        var first = new AuthenticationProviderKey(ProviderType.Oidc, "Google");
        var second = new AuthenticationProviderKey(ProviderType.Oidc, "google");

        Assert.That(first, Is.EqualTo(second));
    }

    [Test]
    public void EqualityShouldUseProviderType()
    {
        var oidc = new AuthenticationProviderKey(ProviderType.Oidc, "Google");
        var oauth = new AuthenticationProviderKey(ProviderType.OAuth, "Google");

        Assert.That(oidc, Is.Not.EqualTo(oauth));
    }

    [Test]
    public void DefaultKeyShouldHaveEmptyName()
    {
        var key = default(AuthenticationProviderKey);
        Assert.That(key.Name, Is.EqualTo(string.Empty));
    }

    [Test]
    public void DefaultKeyShouldHaveDiagnosticToString()
    {
        var key = default(AuthenticationProviderKey);

        Assert.That(key.ToString(), Is.EqualTo("<uninitialized provider>"));
    }

    [Test]
    public void HappyPathToStringShouldWork()
    {
        var key = new AuthenticationProviderKey(ProviderType.Oidc, "Google");
        Assert.That(key.ToString(), Is.EqualTo("OIDC:Google"));
    }
}
