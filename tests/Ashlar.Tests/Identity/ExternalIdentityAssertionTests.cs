using Ashlar.Identity.Models;
using Ashlar.Identity.Providers.External;

namespace Ashlar.Tests.Identity;

public class ExternalIdentityAssertionTests
{
    [Test]
    public void ConstructorShouldRejectNullOrWhiteSpaceProviderKey()
    {
        using (Assert.EnterMultipleScope())
        {
            // ReSharper disable once NullableWarningSuppressionIsUsed
            Assert.Throws<ArgumentNullException>(() => _ = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", null!, new Dictionary<string, string>()));
            Assert.Throws<ArgumentException>(() => _ = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "", new Dictionary<string, string>()));
            Assert.Throws<ArgumentException>(() => _ = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", " ", new Dictionary<string, string>()));
        }
    }

    [Test]
    public void ConstructorShouldRejectNullClaims()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "key", null!));
    }

    [Test]
    public void ConstructorShouldTrimProviderKey()
    {
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", " key ", new Dictionary<string, string>());
        Assert.That(assertion.ProviderKey, Is.EqualTo("key"));
    }

    [Test]
    public void ClaimsShouldBeReadOnlyCopy()
    {
        var claims = new Dictionary<string, string> { { "sub", "123" } };
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "key", claims);

        claims["sub"] = "456";

        Assert.That(assertion.Claims["sub"], Is.EqualTo("123"));
        Assert.Throws<NotSupportedException>(() => assertion.Claims.Add("new", "val"));
    }
}
