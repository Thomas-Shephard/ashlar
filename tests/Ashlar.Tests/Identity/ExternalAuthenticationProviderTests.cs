using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.Providers.External;
using Ashlar.Identity.Providers.Local;
using Ashlar.Security.Hashing;
using Moq;

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

    [Test]
    public void AuthenticateAsyncWithWrongAssertionTypeShouldThrow()
    {
        var assertion = new LocalPasswordAssertion("pass");
        Assert.ThrowsAsync<ArgumentException>(() => _provider.AuthenticateAsync(assertion, null));
    }

    [Test]
    public void AuthenticateAsyncWithNullAssertionShouldThrow()
    {
        Assert.ThrowsAsync<ArgumentException>(() => _provider.AuthenticateAsync(null, null));
    }

    [Test]
    public async Task AuthenticateAsyncWithMismatchedProviderNameShouldReturnFailed()
    {
        var providerKey = "sub-123";
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", providerKey, new Dictionary<string, string>());
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Oidc,
            ProviderName = "NotGoogle",
            ProviderKey = providerKey
        };

        var result = await _provider.AuthenticateAsync(assertion, credential);

        Assert.That(result.Result, Is.EqualTo(PasswordVerificationResult.Failed));
    }

    [Test]
    public void GetProviderKeyWithNonExternalAssertionShouldReturnEmpty()
    {
        var assertion = new Mock<IAuthenticationAssertion>().Object;
        var result = _provider.GetProviderKey(assertion, Guid.NewGuid());
        Assert.That(result, Is.Empty);
    }

    [Test]
    public void GetProviderNameShouldReturnAssertionProviderName()
    {
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "CustomProvider", "key", new Dictionary<string, string>());
        var result = _provider.GetProviderName(assertion);
        Assert.That(result, Is.EqualTo("CustomProvider"));
    }

    [Test]
    public void GetProviderNameWithNonExternalAssertionShouldReturnDefault()
    {
        var assertion = new Mock<IAuthenticationAssertion>().Object;
        var result = _provider.GetProviderName(assertion);
        Assert.That(result, Is.EqualTo(ProviderType.Oidc.Value));
    }

    [Test]
    public void GetProviderNameWithNullAssertionShouldThrow()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _provider.GetProviderName(null!));
    }

    [Test]
    public void GetProviderKeyWithNullAssertionShouldThrow()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _provider.GetProviderKey(null!, Guid.NewGuid()));
    }

    [Test]
    public Task FindUserAsyncWithNullRepositoryShouldThrow()
    {
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "key", new Dictionary<string, string>());
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.ThrowsAsync<ArgumentNullException>(() => _provider.FindUserAsync(assertion, null, null, null!));
        return Task.CompletedTask;
    }

    [Test]
    public async Task FindUserAsyncWithNonExternalAssertionShouldReturnNull()
    {
        var assertion = new Mock<IAuthenticationAssertion>().Object;
        var result = await _provider.FindUserAsync(assertion, null, null, new Mock<IIdentityRepository>().Object);
        Assert.That(result, Is.Null);
    }

    [Test]
    public void PrepareCredentialValueShouldReturnRawValue()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        var result = _provider.PrepareCredentialValue(null!, "raw");
        Assert.That(result, Is.EqualTo("raw"));
    }

    [Test]
    public async Task FindUserAsyncShouldRespectTenantIsolation()
    {
        var tenantId = Guid.NewGuid();
        var otherTenantId = Guid.NewGuid();
        var providerKey = "ext-key";
        var providerName = "Google";
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, providerName, providerKey, new Dictionary<string, string>());

        var user = new User { Id = Guid.NewGuid(), Email = "test@example.com", TenantId = otherTenantId };

        var repoMock = new Mock<IIdentityRepository>();
        repoMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, providerName, providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var result = await _provider.FindUserAsync(assertion, null, tenantId, repoMock.Object);

        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task FindUserAsyncWithTenantUserButNoTenantRequestedShouldReturnNull()
    {
        var providerKey = "ext-key";
        var providerName = "Google";
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, providerName, providerKey, new Dictionary<string, string>());

        var user = new User { Id = Guid.NewGuid(), Email = "test@example.com", TenantId = Guid.NewGuid() };

        var repoMock = new Mock<IIdentityRepository>();
        repoMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, providerName, providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        // Requested tenantId is null, but user has a TenantId
        var result = await _provider.FindUserAsync(assertion, null, null, repoMock.Object);

        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task FindUserAsyncWithGlobalUserAndTenantRequestedShouldReturnNull()
    {
        var tenantId = Guid.NewGuid();
        var providerKey = "ext-key";
        var providerName = "Google";
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, providerName, providerKey, new Dictionary<string, string>());

        // User is global (TenantId is null)
        var user = new User { Id = Guid.NewGuid(), Email = "test@example.com", TenantId = null };

        var repoMock = new Mock<IIdentityRepository>();
        repoMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, providerName, providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        // Requested tenantId is provided, but user is global
        var result = await _provider.FindUserAsync(assertion, null, tenantId, repoMock.Object);

        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task FindUserAsyncWithGlobalUserAndNoTenantRequestedShouldReturnUser()
    {
        var providerKey = "ext-key";
        var providerName = "Google";
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, providerName, providerKey, new Dictionary<string, string>());

        var user = new User { Id = Guid.NewGuid(), Email = "test@example.com", TenantId = null };

        var repoMock = new Mock<IIdentityRepository>();
        repoMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, providerName, providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var result = await _provider.FindUserAsync(assertion, null, null, repoMock.Object);

        Assert.That(result, Is.EqualTo(user));
    }
}
