using Ashlar.Identity.Models;
using Ashlar.Identity.Providers;
using Ashlar.Security.Hashing;

namespace Ashlar.Tests.Identity;

public class ExternalAuthenticationProviderTests
{
    private OidcAuthenticationProvider _provider;

    [SetUp]
    public void SetUp()
    {
        _provider = new OidcAuthenticationProvider();
    }

    [Test]
    public async Task AuthenticateAsyncWithMatchingCredentialShouldReturnSuccess()
    {
        var providerKey = "sub-123";
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", providerKey, new Dictionary<string, string>());
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Oidc,
            ProviderName = "Google",
            ProviderKey = providerKey
        };

        var result = await _provider.AuthenticateAsync(assertion, credential);

        Assert.That(result.Result, Is.EqualTo(PasswordVerificationResult.Success));
    }

    [Test]
    public async Task AuthenticateAsyncWithNullCredentialShouldReturnFailed()
    {
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "sub-123", new Dictionary<string, string>());

        var result = await _provider.AuthenticateAsync(assertion, null);

        Assert.That(result.Result, Is.EqualTo(PasswordVerificationResult.Failed));
    }

    [Test]
    public void AuthenticateAsyncWithMismatchedProviderTypeShouldThrowArgumentException()
    {
        var assertion = new ExternalIdentityAssertion(ProviderType.Saml2, "Okta", "sub", new Dictionary<string, string>());

        Assert.ThrowsAsync<ArgumentException>(() => _provider.AuthenticateAsync(assertion, null));
    }
}
