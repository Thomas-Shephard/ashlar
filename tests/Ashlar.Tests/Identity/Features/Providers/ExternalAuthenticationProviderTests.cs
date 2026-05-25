using Ashlar.Identity.Providers.External;
using Ashlar.Identity.Providers.Local;
using Moq;

namespace Ashlar.Tests.Identity.Features.Providers;

internal sealed class ExternalAuthenticationProviderTests
{
    private OidcAuthenticationProvider _provider;

    [SetUp]
    public void SetUp()
    {
        _provider = new OidcAuthenticationProvider("Google");
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
            ProviderKey = providerKey,
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
        };

        var result = await _provider.AuthenticateAsync(assertion, credential);

        Assert.That(result.Status, Is.EqualTo(AuthenticationResultStatus.Succeeded));
    }

    [Test]
    public async Task AuthenticateAsyncWithNullCredentialShouldReturnFailed()
    {
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "sub-123", new Dictionary<string, string>());

        var result = await _provider.AuthenticateAsync(assertion, null);

        Assert.That(result.Status, Is.EqualTo(AuthenticationResultStatus.Failed));
    }

    [Test]
    public async Task AuthenticateAsyncWithDefaultCredentialProviderTypeShouldReturnFailed()
    {
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "sub-123", new Dictionary<string, string>());
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = default,
            ProviderName = "Google",
            ProviderKey = "sub-123",
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active
        };

        var result = await _provider.AuthenticateAsync(assertion, credential);

        Assert.That(result.Status, Is.EqualTo(AuthenticationResultStatus.Failed));
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
        Assert.ThrowsAsync<ArgumentNullException>(() => _provider.AuthenticateAsync(null!, null));
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
            ProviderKey = providerKey,
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
        };

        var result = await _provider.AuthenticateAsync(assertion, credential);

        Assert.That(result.Status, Is.EqualTo(AuthenticationResultStatus.Failed));
    }

    [Test]
    public void GetProviderKeyWithNonExternalAssertionShouldReturnEmpty()
    {
        var assertion = new Mock<IAuthenticationAssertion>().Object;
        var result = _provider.GetProviderKey(assertion, Guid.NewGuid());
        Assert.That(result, Is.Empty);
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
        Assert.ThrowsAsync<ArgumentNullException>(() => _provider.FindUserAsync(assertion, new AuthenticationContext(), null!));
        return Task.CompletedTask;
    }

    [Test]
    public async Task FindUserAsyncWithNonExternalAssertionShouldReturnNull()
    {
        var assertion = new Mock<IAuthenticationAssertion>().Object;
        var result = await _provider.FindUserAsync(assertion, new AuthenticationContext(), new Mock<IUserRepository>().Object);
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
    public async Task FindUserAsyncShouldReturnProviderKeyUserWhenTenantDiffers()
    {
        var tenantId = Guid.NewGuid();
        var otherTenantId = Guid.NewGuid();
        var providerKey = "ext-key";
        var providerName = "Google";
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, providerName, providerKey, new Dictionary<string, string>());

        var user = new User { Id = Guid.NewGuid(), Email = "test@example.com", TenantId = otherTenantId };

        var repoMock = new Mock<IUserRepository>();
        repoMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, providerName, providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var result = await _provider.FindUserAsync(assertion, new AuthenticationContext(TenantId: tenantId), repoMock.Object);

        Assert.That(result, Is.SameAs(user));
    }

    [Test]
    public async Task FindUserAsyncWithTenantUserButNoTenantRequestedShouldReturnUser()
    {
        var providerKey = "ext-key";
        var providerName = "Google";
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, providerName, providerKey, new Dictionary<string, string>());

        var user = new User { Id = Guid.NewGuid(), Email = "test@example.com", TenantId = Guid.NewGuid() };

        var repoMock = new Mock<IUserRepository>();
        repoMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, providerName, providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var result = await _provider.FindUserAsync(assertion, new AuthenticationContext(), repoMock.Object);

        Assert.That(result, Is.SameAs(user));
    }

    [Test]
    public async Task FindUserAsyncWithGlobalUserAndTenantRequestedShouldReturnUser()
    {
        var tenantId = Guid.NewGuid();
        var providerKey = "ext-key";
        var providerName = "Google";
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, providerName, providerKey, new Dictionary<string, string>());

        var user = new User { Id = Guid.NewGuid(), Email = "test@example.com", TenantId = null };

        var repoMock = new Mock<IUserRepository>();
        repoMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, providerName, providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var result = await _provider.FindUserAsync(assertion, new AuthenticationContext(TenantId: tenantId), repoMock.Object);

        Assert.That(result, Is.SameAs(user));
    }

    [Test]
    public async Task FindUserAsyncWithGlobalUserAndNoTenantRequestedShouldReturnUser()
    {
        var providerKey = "ext-key";
        var providerName = "Google";
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, providerName, providerKey, new Dictionary<string, string>());

        var user = new User { Id = Guid.NewGuid(), Email = "test@example.com", TenantId = null };

        var repoMock = new Mock<IUserRepository>();
        repoMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, providerName, providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var result = await _provider.FindUserAsync(assertion, new AuthenticationContext(), repoMock.Object);

        Assert.That(result, Is.EqualTo(user));
    }

    [Test]
    public async Task FindUserAsyncWithNonTenantUserAndTenantRequestedShouldReturnUser()
    {
        var tenantId = Guid.NewGuid();
        var providerKey = "ext-key";
        var providerName = "Google";
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, providerName, providerKey, new Dictionary<string, string>());
        var user = new GlobalUser(Guid.NewGuid(), "test@example.com");

        var repoMock = new Mock<IUserRepository>();
        repoMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, providerName, providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var result = await _provider.FindUserAsync(assertion, new AuthenticationContext(TenantId: tenantId), repoMock.Object);

        Assert.That(result, Is.SameAs(user));
    }

    [Test]
    public async Task FindUserAsyncWithNonTenantUserAndNoTenantRequestedShouldReturnUser()
    {
        var providerKey = "ext-key";
        var providerName = "Google";
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, providerName, providerKey, new Dictionary<string, string>());
        var user = new GlobalUser(Guid.NewGuid(), "test@example.com");

        var repoMock = new Mock<IUserRepository>();
        repoMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, providerName, providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var result = await _provider.FindUserAsync(assertion, new AuthenticationContext(), repoMock.Object);

        Assert.That(result, Is.SameAs(user));
    }

    private sealed record GlobalUser(Guid Id, string Email) : IUser
    {
        public string? Name => null;
        public bool IsActive => true;
        public DateTimeOffset? EmailVerifiedAt => null;
    }
}
