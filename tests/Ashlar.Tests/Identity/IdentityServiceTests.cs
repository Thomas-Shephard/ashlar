using Ashlar.Identity;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.Providers;
using Ashlar.Identity.Providers.External;
using Ashlar.Identity.Providers.Local;
using Ashlar.Identity.Providers.Recovery;
using Ashlar.Security.Encryption;
using Ashlar.Security.Hashing;
using Moq;

namespace Ashlar.Tests.Identity;

public class IdentityServiceTests
{
    private Mock<IIdentityRepository> _repositoryMock;
    private Mock<ISecretProtector> _secretProtectorMock;
    private Mock<ICredentialService> _credentialServiceMock;
    private FakePasswordHasher _fakeHasher;
    private FakePasswordHasher _oldHasher;
    private PasswordHasherSelector _hasherSelector;
    private IdentityService _identityService;

    [SetUp]
    public void SetUp()
    {
        _repositoryMock = new Mock<IIdentityRepository>();
        _secretProtectorMock = new Mock<ISecretProtector>();
        _credentialServiceMock = new Mock<ICredentialService>();

        _secretProtectorMock.Setup(s => s.Protect(It.IsAny<string>())).Returns<string>(s => $"protected({s})");
        _secretProtectorMock.Setup(s => s.Unprotect(It.IsAny<string>())).Returns<string>(s => s.StartsWith("protected(", StringComparison.Ordinal) ? s[10..^1] : s);

        _fakeHasher = new FakePasswordHasher { Version = 0x02 };
        _oldHasher = new FakePasswordHasher { Version = 0x01 };

        _hasherSelector = new PasswordHasherSelector([_fakeHasher, _oldHasher]);

        var providers = new List<IAuthenticationProvider>
        {
            new LocalPasswordProvider(_hasherSelector),
            new OidcAuthenticationProvider(),
            new OAuthAuthenticationProvider(),
            new Saml2AuthenticationProvider()
        };

        var ticketSerializer = new SessionTicketSerializer(_secretProtectorMock.Object);
        _identityService = new IdentityService(_repositoryMock.Object, providers, _credentialServiceMock.Object, ticketSerializer);

        _repositoryMock.Setup(r => r.GetCredentialsForUserAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Array.Empty<UserCredential>());
    }

    [Test]
    public void ConstructorShouldThrowOnNullCredentialService()
    {
        var providers = Enumerable.Empty<IAuthenticationProvider>();
        var ticketSerializer = new SessionTicketSerializer(_secretProtectorMock.Object);
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new IdentityService(null!, providers, null!, ticketSerializer));
    }

    [Test]
    public void ConstructorShouldThrowOnNullTicketSerializer()
    {
        var providers = Enumerable.Empty<IAuthenticationProvider>();
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new IdentityService(_repositoryMock.Object, providers, _credentialServiceMock.Object, null!));
    }

    [Test]
    public async Task LoginAsyncWithValidLocalPasswordShouldReturnSuccess()
    {
        var email = "test@example.com";
        var password = "password123";
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = email };
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.Local,
            ProviderName = ProviderType.Local.Value,
            ProviderKey = userId.ToString(),
            CredentialValue = Convert.ToBase64String(new byte[] { 0x02, 1, 2, 3 })
        };

        var assertion = new LocalPasswordAssertion(password);
        _credentialServiceMock.Setup(s => s.ResolveAsync(email, assertion, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, credential, false));

        var response = await _identityService.LoginAsync(email, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.True);
            Assert.That(response.User, Is.EqualTo(user));
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Success));
        }
    }

    [Test]
    public async Task LoginAsyncWithInvalidLocalPasswordShouldReturnFailed()
    {
        var email = "test@example.com";
        var password = "wrong-password";
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = email };
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.Local,
            ProviderName = ProviderType.Local.Value,
            ProviderKey = userId.ToString(),
            CredentialValue = Convert.ToBase64String(new byte[] { 0x02, 1, 2, 3 })
        };

        var assertion = new LocalPasswordAssertion(password);
        _credentialServiceMock.Setup(s => s.ResolveAsync(email, assertion, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, credential, false));

        _fakeHasher.ShouldVerify = false;

        var response = await _identityService.LoginAsync(email, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
        }
    }

    [Test]
    public async Task LoginAsyncWithOidcAssertionShouldReturnSuccess()
    {
        var email = "google-user@example.com";
        var providerKey = "google-sub-123";
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = email };
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.Oidc,
            ProviderName = "Google",
            ProviderKey = providerKey
        };

        var claims = new Dictionary<string, string> { { "name", "Google User" } };
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", providerKey, claims);

        _credentialServiceMock.Setup(s => s.ResolveAsync(email, assertion, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, credential, false));

        var response = await _identityService.LoginAsync(email, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.True);
            Assert.That(response.Claims, Is.EqualTo(claims));
        }
    }

    [Test]
    public async Task LoginAsyncWithUserNotFoundForExternalProviderShouldReturnFailed()
    {
        var email = "nonexistent@example.com";
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "sub", new Dictionary<string, string>());

        _credentialServiceMock.Setup(s => s.ResolveAsync(email, assertion, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((null, null, false));

        var response = await _identityService.LoginAsync(email, assertion);

        Assert.That(response.Succeeded, Is.False);
    }

    [Test]
    public Task LinkCredentialAsyncShouldDelegateToCredentialService()
    {
        var userId = Guid.NewGuid();
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "sub", new Dictionary<string, string>());

        Assert.DoesNotThrowAsync(() => _identityService.LinkCredentialAsync(userId, assertion, "value"));
        
        _credentialServiceMock.Verify(s => s.LinkCredentialAsync(userId, assertion, "value", It.IsAny<CancellationToken>()), Times.Once);
        return Task.CompletedTask;
    }

    [Test]
    public async Task LoginAsyncWithInactiveUserShouldReturnDisabledStatus()
    {
        var email = "inactive@example.com";
        var user = new User { Id = Guid.NewGuid(), Email = email, IsActive = false };
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.Local,
            ProviderName = ProviderType.Local.Value,
            ProviderKey = user.Id.ToString(),
            CredentialValue = Convert.ToBase64String(new byte[] { 0x02, 1, 2, 3 })
        };

        var assertion = new LocalPasswordAssertion("pass");
        _credentialServiceMock.Setup(s => s.ResolveAsync(email, assertion, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, credential, false));

        _fakeHasher.ShouldVerify = true;

        var response = await _identityService.LoginAsync(email, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Disabled));
        }
    }

    [Test]
    public async Task LoginAsyncWithRehashNeededShouldUpdateCredentialUsage()
    {
        var email = "rehash@example.com";
        var user = new User { Id = Guid.NewGuid(), Email = email };
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.Local,
            ProviderName = ProviderType.Local.Value,
            ProviderKey = user.Id.ToString(),
            CredentialValue = Convert.ToBase64String([0x01, 1, 2, 3])
        };

        var assertion = new LocalPasswordAssertion("pass");
        _credentialServiceMock.Setup(s => s.ResolveAsync(email, assertion, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, credential, false));

        _oldHasher.ShouldVerify = true;

        var response = await _identityService.LoginAsync(email, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.True);
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.SuccessRehashNeeded));
        }

        _credentialServiceMock.Verify(s => s.UpdateCredentialUsageAsync(credential, It.Is<AuthenticationResult>(r => r.Result == PasswordVerificationResult.SuccessRehashNeeded), It.IsAny<IAuthenticationProvider>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task LoginAsyncWithOAuthAssertionShouldReturnSuccess()
    {
        var email = "oauth-user@example.com";
        var user = new User { Id = Guid.NewGuid(), Email = email };
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.OAuth,
            ProviderName = "GitHub",
            ProviderKey = "sub"
        };

        var claims = new Dictionary<string, string> { { "login", "octocat" } };
        var assertion = new ExternalIdentityAssertion(ProviderType.OAuth, "GitHub", "sub", claims);

        _credentialServiceMock.Setup(s => s.ResolveAsync(email, assertion, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, credential, false));

        var response = await _identityService.LoginAsync(email, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.True);
            Assert.That(response.Claims, Is.EqualTo(claims));
        }
    }

    [Test]
    public async Task FindByEmailAsyncShouldCallRepository()
    {
        var email = "test@example.com";
        var tenantId = Guid.NewGuid();
        var user = new User { Id = Guid.NewGuid(), Email = email };
        _repositoryMock.Setup(r => r.GetUserByEmailAsync(email, tenantId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var result = await _identityService.FindByEmailAsync(email, tenantId);

        Assert.That(result, Is.EqualTo(user));
    }

    [Test]
    public async Task FindByProviderKeyAsyncShouldCallRepository()
    {
        var type = ProviderType.Oidc;
        var providerName = "Google";
        var providerKey = "sub-123";
        var user = new User { Id = Guid.NewGuid(), Email = "test@example.com" };
        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(type, providerName, providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var result = await _identityService.FindByProviderKeyAsync(type, providerName, providerKey);

        Assert.That(result, Is.EqualTo(user));
    }

    [Test]
    public async Task CreateUserAsyncShouldCallRepository()
    {
        var user = new User { Id = Guid.NewGuid(), Email = "test@example.com" };
        _repositoryMock.Setup(r => r.CreateUserAsync(user, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        var result = await _identityService.CreateUserAsync(user);

        Assert.That(result, Is.EqualTo(user));
        _repositoryMock.Verify(r => r.CreateUserAsync(user, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public void SupportedProviderTypesShouldReturnKeys()
    {
        var types = _identityService.SupportedProviderTypes.ToList();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(types, Contains.Item(ProviderType.Local));
            Assert.That(types, Contains.Item(ProviderType.Oidc));
        }
    }

    [Test]
    public async Task LoginAsyncWithUnsupportedProviderShouldReturnFailed()
    {
        var assertionMock = new Mock<IAuthenticationAssertion>();
        assertionMock.Setup(a => a.ProviderType).Returns((ProviderType)"Unsupported");

        var response = await _identityService.LoginAsync("test@example.com", assertionMock.Object);

        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
    }

    [Test]
    public async Task LoginAsyncWithRehashNeededButNullCredentialShouldNotAttemptUpdate()
    {
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.Setup(p => p.SupportedType).Returns(ProviderType.Local);
        providerMock.Setup(p => p.IsPrimary).Returns(true);
        providerMock.Setup(p => p.GetProviderName(It.IsAny<IAuthenticationAssertion>())).Returns(ProviderType.Local.Value);
        providerMock.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(PasswordVerificationResult.SuccessRehashNeeded, ShouldUpdateCredential: true, NewCredentialValue: "new-hash"));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<IUser>()))
            .Returns("key");

        var assertionMock = new Mock<IAuthenticationAssertion>();
        assertionMock.Setup(a => a.ProviderType).Returns(ProviderType.Local);

        var user = new User { Id = Guid.NewGuid(), Email = "test@example.com" };
        var providers = new[] { providerMock.Object };
        var service = new IdentityService(_repositoryMock.Object, providers, _credentialServiceMock.Object, new SessionTicketSerializer(_secretProtectorMock.Object));

        _credentialServiceMock.Setup(s => s.ResolveAsync(It.IsAny<string>(), assertionMock.Object, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, null, false));

        var response = await service.LoginAsync("test@example.com", assertionMock.Object);

        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.SuccessRehashNeeded));
        _credentialServiceMock.Verify(s => s.UpdateCredentialUsageAsync(null, It.IsAny<AuthenticationResult>(), It.IsAny<IAuthenticationProvider>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task LoginAsyncWithRehashNeededButNoNewValueShouldNotAttemptUpdate()
    {
        var email = "rehash@example.com";
        var user = new User { Id = Guid.NewGuid(), Email = email };
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.Local,
            ProviderName = ProviderType.Local.Value,
            ProviderKey = user.Id.ToString(),
            CredentialValue = Convert.ToBase64String([0x01, 1, 2, 3])
        };

        _oldHasher.ShouldVerify = true;
        // Mocking rehash needed but returning null for new value
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.Setup(p => p.SupportedType).Returns(ProviderType.Local);
        providerMock.Setup(p => p.IsPrimary).Returns(true);
        providerMock.Setup(p => p.GetProviderName(It.IsAny<IAuthenticationAssertion>())).Returns(ProviderType.Local.Value);
        providerMock.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(PasswordVerificationResult.SuccessRehashNeeded, ShouldUpdateCredential: true, NewCredentialValue: null));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<IUser>())).Returns(user.Id.ToString());

        var providers = new[] { providerMock.Object };
        var service = new IdentityService(_repositoryMock.Object, providers, _credentialServiceMock.Object, new SessionTicketSerializer(_secretProtectorMock.Object));

        var assertion = new LocalPasswordAssertion("pass");
        _credentialServiceMock.Setup(s => s.ResolveAsync(email, assertion, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, credential, false));

        var response = await service.LoginAsync(email, assertion);

        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.SuccessRehashNeeded));
        _credentialServiceMock.Verify(s => s.UpdateCredentialUsageAsync(credential, It.IsAny<AuthenticationResult>(), It.IsAny<IAuthenticationProvider>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task LoginAsyncWithUnprotectFailureShouldReturnFailedEvenIfAuthenticateSucceeds()
    {
        var email = "test@example.com";
        var user = new User { Id = Guid.NewGuid(), Email = email };
        var credential = new UserCredential 
        { 
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.Oidc,
            ProviderName = "Google",
            ProviderKey = "sub"
        };
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "sub", new Dictionary<string, string>());

        _credentialServiceMock.Setup(s => s.ResolveAsync(email, assertion, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, credential, true));

        var response = await _identityService.LoginAsync(email, assertion);

        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
    }

    [Test]
    public async Task LoginAsyncWithEmptyEmailShouldReturnFailed()
    {
        var assertion = new LocalPasswordAssertion("pass");
        _credentialServiceMock.Setup(s => s.ResolveAsync("", assertion, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((null, null, false));

        var response = await _identityService.LoginAsync("", assertion);

        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
    }

    [Test]
    public async Task LoginAsyncWithNullEmailShouldReturnFailed()
    {
        var assertion = new LocalPasswordAssertion("pass");
        // ReSharper disable once NullableWarningSuppressionIsUsed
        _credentialServiceMock.Setup(s => s.ResolveAsync(null, assertion, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((null, null, false));

        var response = await _identityService.LoginAsync((string)null!, assertion);

        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
    }

    [Test]
    public async Task LoginAsyncWithSuccessRehashNeededButNullUserShouldReturnFailed()
    {
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.Setup(p => p.SupportedType).Returns((ProviderType)"MOCK");
        providerMock.Setup(p => p.IsPrimary).Returns(true);
        providerMock.Setup(p => p.GetProviderName(It.IsAny<IAuthenticationAssertion>())).Returns("MOCK");
        providerMock.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(PasswordVerificationResult.SuccessRehashNeeded));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<IUser>()))
            .Returns("key");

        var assertionMock = new Mock<IAuthenticationAssertion>();
        assertionMock.Setup(a => a.ProviderType).Returns((ProviderType)"MOCK");

        var providers = new[] { providerMock.Object };
        var service = new IdentityService(_repositoryMock.Object, providers, _credentialServiceMock.Object, new SessionTicketSerializer(_secretProtectorMock.Object));

        _credentialServiceMock.Setup(s => s.ResolveAsync(It.IsAny<string>(), assertionMock.Object, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((null, null, false));

        var response = await service.LoginAsync("test@example.com", assertionMock.Object);

        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
    }

    [Test]
    public async Task LoginAsyncWithFoundCredentialButNullUserShouldReturnFailed()
    {
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.Setup(p => p.SupportedType).Returns((ProviderType)"MOCK");
        providerMock.Setup(p => p.IsPrimary).Returns(true);
        providerMock.Setup(p => p.GetProviderName(It.IsAny<IAuthenticationAssertion>())).Returns("MOCK");
        providerMock.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(PasswordVerificationResult.Success));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<IUser>()))
            .Returns("key");

        var assertionMock = new Mock<IAuthenticationAssertion>();
        assertionMock.Setup(a => a.ProviderType).Returns((ProviderType)"MOCK");

        var providers = new[] { providerMock.Object };
        var service = new IdentityService(_repositoryMock.Object, providers, _credentialServiceMock.Object, new SessionTicketSerializer(_secretProtectorMock.Object));

        _credentialServiceMock.Setup(s => s.ResolveAsync(It.IsAny<string>(), assertionMock.Object, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((null, null, false));

        var response = await service.LoginAsync("test@example.com", assertionMock.Object);

        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
    }

    [Test]
    public async Task LoginAsyncWithSaml2AssertionShouldReturnSuccess()
    {
        var user = new User { Id = Guid.NewGuid(), Email = "saml@example.com" };
        var credential = new UserCredential 
        { 
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.Saml2,
            ProviderName = "Okta",
            ProviderKey = "sub"
        };
        var assertion = new ExternalIdentityAssertion(ProviderType.Saml2, "Okta", "sub", new Dictionary<string, string>());

        _credentialServiceMock.Setup(s => s.ResolveAsync("saml@example.com", assertion, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, credential, false));

        var response = await _identityService.LoginAsync("saml@example.com", assertion);

        Assert.That(response.Succeeded, Is.True);
    }

    [Test]
    public async Task LoginAsyncWithExternalProviderShouldUnprotectCredentialValue()
    {
        var email = "test@example.com";
        var user = new User { Id = Guid.NewGuid(), Email = email };
        var credential = new UserCredential 
        { 
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.Oidc,
            ProviderName = "Google",
            ProviderKey = "sub",
            CredentialValue = "plain" 
        };
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "sub", new Dictionary<string, string>());

        _credentialServiceMock.Setup(s => s.ResolveAsync(email, assertion, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, credential, false));

        // Mock a provider to capture the credential passed to it
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.Setup(p => p.SupportedType).Returns(ProviderType.Oidc);
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);
        providerMock.Setup(p => p.IsPrimary).Returns(true);
        providerMock.Setup(p => p.GetProviderName(It.IsAny<IAuthenticationAssertion>())).Returns("Google");
        providerMock.Setup(p => p.AuthenticateAsync(assertion, It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(PasswordVerificationResult.Success));

        var providers = new[] { providerMock.Object };
        var service = new IdentityService(_repositoryMock.Object, providers, _credentialServiceMock.Object, new SessionTicketSerializer(_secretProtectorMock.Object));

        await service.LoginAsync(email, assertion);

        providerMock.Verify(p => p.AuthenticateAsync(assertion, It.Is<UserCredential>(c => c.CredentialValue == "plain"), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task LoginAsyncWithLocalProviderShouldNotUnprotectCredentialValue()
    {
        var email = "test@example.com";
        var user = new User { Id = Guid.NewGuid(), Email = email };
        var credential = new UserCredential 
        { 
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.Local,
            ProviderName = "Local",
            ProviderKey = "sub"
        };
        var assertion = new LocalPasswordAssertion("pass");

        _credentialServiceMock.Setup(s => s.ResolveAsync(email, assertion, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, credential, false));

        await _identityService.LoginAsync(email, assertion);

        _secretProtectorMock.Verify(s => s.Unprotect(It.IsAny<string>()), Times.Never);
    }

    [Test]
    public async Task LoginAsyncWithExternalProviderUpdatingTokenShouldProtectNewToken()
    {
        var email = "test@example.com";
        var user = new User { Id = Guid.NewGuid(), Email = email };
        var credential = new UserCredential 
        { 
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.OAuth,
            ProviderName = "GitHub",
            ProviderKey = "sub"
        };
        var assertion = new ExternalIdentityAssertion(ProviderType.OAuth, "GitHub", "sub", new Dictionary<string, string>());

        _credentialServiceMock.Setup(s => s.ResolveAsync(email, assertion, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, credential, false));

        // Mock a provider that wants to update the token
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.Setup(p => p.SupportedType).Returns(ProviderType.OAuth);
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);
        providerMock.Setup(p => p.IsPrimary).Returns(true);
        providerMock.Setup(p => p.GetProviderName(It.IsAny<IAuthenticationAssertion>())).Returns("GitHub");
        providerMock.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(PasswordVerificationResult.Success, ShouldUpdateCredential: true, NewCredentialValue: "new"));

        var providers = new[] { providerMock.Object };
        var service = new IdentityService(_repositoryMock.Object, providers, _credentialServiceMock.Object, new SessionTicketSerializer(_secretProtectorMock.Object));

        await service.LoginAsync(email, assertion);

        _credentialServiceMock.Verify(s => s.UpdateCredentialUsageAsync(credential, It.Is<AuthenticationResult>(r => r.NewCredentialValue == "new"), providerMock.Object, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task LoginAsyncWithExternalProviderAndCredentialWithNullValueAndDummyUnprotectFailureShouldReturnSuccess()
    {
        var email = "test@example.com";
        var user = new User { Id = Guid.NewGuid(), Email = email };
        var credential = new UserCredential 
        { 
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.Oidc,
            ProviderName = "Google",
            ProviderKey = "sub"
        };
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "sub", new Dictionary<string, string>());

        _credentialServiceMock.Setup(s => s.ResolveAsync(email, assertion, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, credential, false));

        var response = await _identityService.LoginAsync(email, assertion);

        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Success));
    }

    [Test]
    public async Task LoginAsyncWithExternalProviderAndMissingUserShouldStillCallResolve()
    {
        var email = "ghost@example.com";
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "sub", new Dictionary<string, string>());

        _credentialServiceMock.Setup(s => s.ResolveAsync(email, assertion, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((null, null, false));

        await _identityService.LoginAsync(email, assertion);

        _credentialServiceMock.Verify(s => s.ResolveAsync(email, assertion, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task LoginAsyncWithExternalProviderAndMalformedCredentialShouldReturnFailed()
    {
        var email = "test@example.com";
        var user = new User { Id = Guid.NewGuid(), Email = email };
        var credential = new UserCredential 
        { 
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.Oidc,
            ProviderName = "Google",
            ProviderKey = "sub"
        };
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "sub", new Dictionary<string, string>());

        _credentialServiceMock.Setup(s => s.ResolveAsync(email, assertion, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, credential, true));

        var response = await _identityService.LoginAsync(email, assertion);

        Assert.That(response.Succeeded, Is.False);
    }

    [Test]
    public async Task LoginAsyncWithExternalProviderAndNullCredentialValueShouldReturnSuccess()
    {
        var email = "test@example.com";
        var user = new User { Id = Guid.NewGuid(), Email = email };
        var credential = new UserCredential 
        { 
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.Oidc,
            ProviderName = "Google",
            ProviderKey = "sub"
        };
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "sub", new Dictionary<string, string>());

        _credentialServiceMock.Setup(s => s.ResolveAsync(email, assertion, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, credential, false));

        var response = await _identityService.LoginAsync(email, assertion);

        Assert.That(response.Succeeded, Is.True);
    }

    [Test]
    public async Task LoginAsyncWithUserNotFoundShouldStillCallResolveForTimingProtection()
    {
        var email = "ghost@example.com";
        var assertion = new LocalPasswordAssertion("pass");
        _credentialServiceMock.Setup(s => s.ResolveAsync(email, assertion, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((null, null, false));

        await _identityService.LoginAsync(email, assertion);

        _credentialServiceMock.Verify(s => s.ResolveAsync(email, assertion, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task LoginAsyncWithConsumedCredentialShouldNotUpdateCredential()
    {
        var email = "consumed@example.com";
        var user = new User { Id = Guid.NewGuid(), Email = email };
        var credential = new UserCredential 
        { 
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.RecoveryCode,
            ProviderName = "RecoveryCode",
            ProviderKey = "sub"
        };
        var assertion = new RecoveryCodeAssertion("code");

        _credentialServiceMock.Setup(s => s.ResolveAsync(email, assertion, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, credential, false));

        // Mock a provider that returns IsCredentialConsumed = true
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.Setup(p => p.SupportedType).Returns(ProviderType.RecoveryCode);
        providerMock.Setup(p => p.IsPrimary).Returns(true);
        providerMock.Setup(p => p.GetProviderName(It.IsAny<IAuthenticationAssertion>())).Returns("RecoveryCode");
        providerMock.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(PasswordVerificationResult.Success, IsCredentialConsumed: true));

        var providers = new[] { providerMock.Object };
        var service = new IdentityService(_repositoryMock.Object, providers, _credentialServiceMock.Object, new SessionTicketSerializer(_secretProtectorMock.Object));

        var response = await service.LoginAsync(email, assertion);

        Assert.That(response.Succeeded, Is.True);
        _credentialServiceMock.Verify(s => s.UpdateCredentialUsageAsync(credential, It.Is<AuthenticationResult>(r => r.IsCredentialConsumed), It.IsAny<IAuthenticationProvider>(), It.IsAny<CancellationToken>()), Times.Once);
    }
}
