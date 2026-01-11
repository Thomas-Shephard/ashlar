using Ashlar.Identity;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.Providers;
using Ashlar.Security.Encryption;
using Ashlar.Security.Hashing;
using Moq;

namespace Ashlar.Tests.Identity;

public class IdentityServiceTests
{
    private Mock<IIdentityRepository> _repositoryMock;
    private Mock<ISecretProtector> _secretProtectorMock;
    private FakePasswordHasher _fakeHasher;
    private FakePasswordHasher _oldHasher;
    private PasswordHasherSelector _hasherSelector;
    private IdentityService _identityService;

    [SetUp]
    public void SetUp()
    {
        _repositoryMock = new Mock<IIdentityRepository>();
        _secretProtectorMock = new Mock<ISecretProtector>();

        // Default behavior: return as-is for simplicity in existing tests,
        // unless we specifically want to test protection.
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

        _identityService = new IdentityService(_repositoryMock.Object, providers, _secretProtectorMock.Object);
    }

    [Test]
    public void ConstructorShouldThrowOnNullRepository()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new IdentityService(null!, [], _secretProtectorMock.Object));
    }

    [Test]
    public void ConstructorShouldThrowOnNullProviders()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new IdentityService(_repositoryMock.Object, null!, _secretProtectorMock.Object));
    }

    [Test]
    public void ConstructorShouldThrowOnDuplicateProviderType()
    {
        var providers = new[]
        {
            new OidcAuthenticationProvider(),
            new OidcAuthenticationProvider()
        };

        Assert.Throws<ArgumentException>(() => _ = new IdentityService(_repositoryMock.Object, providers, _secretProtectorMock.Object));
    }

    [Test]
    public void ConstructorShouldThrowOnNullSecretProtector()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new IdentityService(_repositoryMock.Object, [], null!));
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

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(email, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Local, ProviderType.Local.Value, userId.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var response = await _identityService.LoginAsync(email, new LocalPasswordAssertion(password));

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

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(email, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Local, ProviderType.Local.Value, userId.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        _fakeHasher.ShouldVerify = false;

        var response = await _identityService.LoginAsync(email, new LocalPasswordAssertion(password));

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

        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, "Google", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Oidc, "Google", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

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
        var providerName = "Google";
        var providerKey = "sub";
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, providerName, providerKey, new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, providerName, providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync((IUser?)null);

        var response = await _identityService.LoginAsync(email, assertion);

        Assert.That(response.Succeeded, Is.False);
    }

    [Test]
    public async Task LoginAsyncWithExternalProviderShouldPassProviderNameToRepository()
    {
        var email = "test@example.com";
        var providerName = "GitHub";
        var providerKey = "gh-123";
        var user = new User { Id = Guid.NewGuid(), Email = email };
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.Oidc,
            ProviderName = providerName,
            ProviderKey = providerKey
        };
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, providerName, providerKey, new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, providerName, providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Oidc, providerName, providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        await _identityService.LoginAsync(email, assertion);

        _repositoryMock.Verify(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Oidc, providerName, providerKey, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public Task LinkCredentialAsyncWithExistingCredentialShouldThrowInvalidOperationException()
    {
        var userId = Guid.NewGuid();
        var type = ProviderType.Oidc;
        var providerName = "Google";
        var providerKey = "sub";
        var user = new User { Id = userId, Email = "test@example.com" };

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(type, providerName, providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        Assert.ThrowsAsync<InvalidOperationException>(() =>
            _identityService.LinkCredentialAsync(userId, new ExternalIdentityAssertion(type, providerName, providerKey, new Dictionary<string, string>())));
        return Task.CompletedTask;
    }

    [Test]
    public async Task LinkCredentialAsyncWithNewCredentialShouldCallRepositoryCreate()
    {
        var userId = Guid.NewGuid();
        var type = ProviderType.Oidc;
        var providerName = "Google";
        var providerKey = "sub";
        var assertion = new ExternalIdentityAssertion(type, providerName, providerKey, new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, Email = "test@example.com" });
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, type, providerName, providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync((UserCredential?)null);

        await _identityService.LinkCredentialAsync(userId, assertion);

        _repositoryMock.Verify(r => r.CreateCredentialAsync(It.Is<UserCredential>(c =>
            c.UserId == userId &&
            c.ProviderType == type &&
            c.ProviderName == providerName &&
            c.ProviderKey == providerKey), It.IsAny<CancellationToken>()), Times.Once);
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

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(email, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Local, ProviderType.Local.Value, user.Id.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);
        _fakeHasher.ShouldVerify = true;

        var response = await _identityService.LoginAsync(email, new LocalPasswordAssertion("pass"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Disabled));
        }
    }

    [Test]
    public async Task LoginAsyncWithExternalAssertionShouldFindUserByProviderKey()
    {
        var email = "test@example.com";
        var providerName = "Google";
        var providerKey = "sub-123";
        var user = new User { Id = Guid.NewGuid(), Email = email };
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.Oidc,
            ProviderName = providerName,
            ProviderKey = providerKey
        };
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, providerName, providerKey, new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, providerName, providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Oidc, providerName, providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var response = await _identityService.LoginAsync(email, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.True);
            Assert.That(response.User, Is.EqualTo(user));
        }

        _repositoryMock.Verify(r => r.GetUserByEmailAsync(It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task LoginAsyncWithRehashNeededShouldUpdateCredential()
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

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(email, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Local, ProviderType.Local.Value, user.Id.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        _oldHasher.ShouldVerify = true;
        var expectedHash = Convert.ToBase64String(new byte[] { 0x02, 0, 0, 0 });

        var response = await _identityService.LoginAsync(email, new LocalPasswordAssertion("pass"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.True);
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.SuccessRehashNeeded));
        }

        _repositoryMock.Verify(r => r.UpdateCredentialAsync(It.Is<UserCredential>(c =>
            c.Id == credential.Id &&
            c.CredentialValue == expectedHash), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task LinkCredentialAsyncWithLocalPasswordShouldHashPassword()
    {
        var userId = Guid.NewGuid();
        var password = "plain-password";
        var expectedHash = Convert.ToBase64String(new byte[] { 0x02, 0, 0, 0 });

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, Email = "test@example.com" });
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Local, ProviderType.Local.Value, It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((UserCredential?)null);

        await _identityService.LinkCredentialAsync(userId, new LocalPasswordAssertion(password), password);

        _repositoryMock.Verify(r => r.CreateCredentialAsync(It.Is<UserCredential>(c =>
            c.UserId == userId &&
            c.CredentialValue == expectedHash), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public void LinkCredentialAsyncWithEmptyUserIdShouldThrowArgumentException()
    {
        Assert.ThrowsAsync<ArgumentException>(() =>
            _identityService.LinkCredentialAsync(Guid.Empty, new LocalPasswordAssertion("pass"), "pass"));
    }

    [Test]
    public Task LinkCredentialAsyncWithAlreadyLinkedToAnotherUserShouldThrowInvalidOperationException()
    {
        var userId = Guid.NewGuid();
        var anotherUserId = Guid.NewGuid();
        var type = ProviderType.Oidc;
        var providerName = "Google";
        var providerKey = "sub-123";
        var anotherUser = new User { Id = anotherUserId, Email = "another@example.com" };
        var assertion = new ExternalIdentityAssertion(type, providerName, providerKey, new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, Email = "user@example.com" });
        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(type, providerName, providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(anotherUser);

        var ex = Assert.ThrowsAsync<InvalidOperationException>(() =>
            _identityService.LinkCredentialAsync(userId, assertion));
        Assert.That(ex.Message, Is.EqualTo($"The credential from '{providerName}' is already linked to another user."));
        return Task.CompletedTask;
    }

    [Test]
    public async Task LinkCredentialAsyncWithLocalTypeShouldForceProviderNameToLocal()
    {
        var userId = Guid.NewGuid();
        var type = ProviderType.Local;
        var password = "password";

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, Email = "test@example.com" });
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, type, ProviderType.Local.Value, userId.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((UserCredential?)null);

        await _identityService.LinkCredentialAsync(userId, new LocalPasswordAssertion(password), password);

        _repositoryMock.Verify(r => r.CreateCredentialAsync(It.Is<UserCredential>(c =>
            c.ProviderName == ProviderType.Local.Value), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public void LinkCredentialAsyncWithLocalTypeAndMissingPasswordShouldThrowArgumentException()
    {
        var userId = Guid.NewGuid();

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, Email = "test@example.com" });

        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.CatchAsync<ArgumentException>(() => _identityService.LinkCredentialAsync(userId, new LocalPasswordAssertion(null!)));
    }

    [Test]
    public async Task LoginAsyncWithOAuthAssertionShouldReturnSuccess()
    {
        var email = "oauth-user@example.com";
        var providerKey = "oauth-sub-123";
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = email };
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.OAuth,
            ProviderName = "GitHub",
            ProviderKey = providerKey
        };

        var claims = new Dictionary<string, string> { { "login", "octocat" } };
        var assertion = new ExternalIdentityAssertion(ProviderType.OAuth, "GitHub", providerKey, claims);

        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.OAuth, "GitHub", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.OAuth, "GitHub", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var response = await _identityService.LoginAsync(email, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.True);
            Assert.That(response.Claims, Is.EqualTo(claims));
        }
    }

    [Test]
    public async Task LoginAsyncWithRehashUpdateExceptionShouldStillReturnSuccess()
    {
        var email = "rehash-fail@example.com";
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

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(email, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Local, ProviderType.Local.Value, user.Id.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);
        _repositoryMock.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("DB error"));

        _oldHasher.ShouldVerify = true;

        var response = await _identityService.LoginAsync(email, new LocalPasswordAssertion("pass"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.True);
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.SuccessRehashNeeded));
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
    public void LinkCredentialAsyncWithNonExistentUserShouldThrow()
    {
        var userId = Guid.NewGuid();
        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync((IUser?)null);

        Assert.ThrowsAsync<InvalidOperationException>(() =>
            _identityService.LinkCredentialAsync(userId, new LocalPasswordAssertion("pass")));
    }

    [Test]
    public void LinkCredentialAsyncWithUnsupportedProviderShouldThrow()
    {
        var userId = Guid.NewGuid();
        var assertionMock = new Mock<IAuthenticationAssertion>();
        assertionMock.Setup(a => a.ProviderType).Returns((ProviderType)"Unsupported");

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, Email = "test@example.com" });

        Assert.ThrowsAsync<ArgumentException>(() =>
            _identityService.LinkCredentialAsync(userId, assertionMock.Object));
    }

    [Test]
    public Task LinkCredentialAsyncWithSameUserAlreadyLinkedShouldThrow()
    {
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = "test@example.com" };
        var assertion = new LocalPasswordAssertion("pass");

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Local, ProviderType.Local.Value, userId.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var ex = Assert.ThrowsAsync<InvalidOperationException>(() =>
            _identityService.LinkCredentialAsync(userId, assertion));
        Assert.That(ex.Message, Is.EqualTo("A local password is already linked to this user."));
        return Task.CompletedTask;
    }

    [Test]
    public Task LinkCredentialAsyncWithSameUserAlreadyLinkedExternalShouldThrow()
    {
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = "test@example.com" };
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "sub", new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var ex = Assert.ThrowsAsync<InvalidOperationException>(() =>
            _identityService.LinkCredentialAsync(userId, assertion));
        Assert.That(ex.Message, Is.EqualTo("Credential for provider 'Google' is already linked to this user."));
        return Task.CompletedTask;
    }

    [Test]
    public async Task LoginAsyncWithRehashNeededButNullCredentialShouldNotAttemptUpdate()
    {
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.Setup(p => p.SupportedType).Returns((ProviderType)"MOCK");
        providerMock.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(PasswordVerificationResult.SuccessRehashNeeded, ShouldUpdateCredential: true, NewCredentialValue: "new-hash"));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<IUser>()))
            .Returns("key");

        var assertionMock = new Mock<IAuthenticationAssertion>();
        assertionMock.Setup(a => a.ProviderType).Returns((ProviderType)"MOCK");

        var user = new User { Id = Guid.NewGuid(), Email = "test@example.com" };
        var service = new IdentityService(_repositoryMock.Object, [providerMock.Object], _secretProtectorMock.Object);

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, (ProviderType)"MOCK", "MOCK", "key", It.IsAny<CancellationToken>()))
            .ReturnsAsync((UserCredential?)null);

        var response = await service.LoginAsync("test@example.com", assertionMock.Object);

        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.SuccessRehashNeeded));
        _repositoryMock.Verify(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()), Times.Never);
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

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(email, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Local, ProviderType.Local.Value, user.Id.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        _oldHasher.ShouldVerify = true;
        // Mocking rehash needed but returning null for new value
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.Setup(p => p.SupportedType).Returns(ProviderType.Local);
        providerMock.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(PasswordVerificationResult.SuccessRehashNeeded, ShouldUpdateCredential: true, NewCredentialValue: null));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<IUser>())).Returns(user.Id.ToString());

        var service = new IdentityService(_repositoryMock.Object, [providerMock.Object], _secretProtectorMock.Object);

        var response = await service.LoginAsync(email, new LocalPasswordAssertion("pass"));

        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.SuccessRehashNeeded));
        _repositoryMock.Verify(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task LoginAsyncWithEmptyEmailShouldReturnFailed()
    {
        var response = await _identityService.LoginAsync("", new LocalPasswordAssertion("pass"));

        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
    }

    [Test]
    public void LinkCredentialAsyncWithEmptyProviderNameShouldThrow()
    {
        var userId = Guid.NewGuid();
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "", "key", new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, Email = "a@b.com" });

        Assert.ThrowsAsync<ArgumentException>(() => _identityService.LinkCredentialAsync(userId, assertion));
    }

    [Test]
    public async Task LoginAsyncWithNullEmailShouldReturnFailed()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        var response = await _identityService.LoginAsync(null!, new LocalPasswordAssertion("pass"));

        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
        _repositoryMock.Verify(r => r.GetCredentialForUserAsync(It.IsAny<Guid>(), ProviderType.Local, ProviderType.Local.Value, It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public void LinkCredentialAsyncWithProviderKeyDerivationFailureShouldThrow()
    {
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = "test@example.com" };

        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.Setup(p => p.SupportedType).Returns((ProviderType)"MOCK");
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<IUser>()))
            .Returns(string.Empty);

        var assertionMock = new Mock<IAuthenticationAssertion>();
        assertionMock.Setup(a => a.ProviderType).Returns((ProviderType)"MOCK");

        var service = new IdentityService(_repositoryMock.Object, [providerMock.Object], _secretProtectorMock.Object);

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.LinkCredentialAsync(userId, assertionMock.Object));
    }

    [Test]
    public void LoginAsyncWithNullAssertionShouldThrow()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.ThrowsAsync<ArgumentNullException>(() => _identityService.LoginAsync("test@example.com", null!));
    }

    [Test]
    public async Task LoginAsyncWithSuccessRehashNeededButNullUserShouldReturnFailed()
    {
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.Setup(p => p.SupportedType).Returns((ProviderType)"MOCK");
        providerMock.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(PasswordVerificationResult.SuccessRehashNeeded));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<IUser>()))
            .Returns("key");

        var assertionMock = new Mock<IAuthenticationAssertion>();
        assertionMock.Setup(a => a.ProviderType).Returns((ProviderType)"MOCK");

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((IUser?)null);

        var service = new IdentityService(_repositoryMock.Object, [providerMock.Object], _secretProtectorMock.Object);

        var response = await service.LoginAsync("test@example.com", assertionMock.Object);

        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
    }

    [Test]
    public Task LinkCredentialAsyncWithExternalAssertionAlreadyLinkedToSameUserShouldThrow()
    {
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = "test@example.com" };
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "sub", new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var ex = Assert.ThrowsAsync<InvalidOperationException>(() =>
            _identityService.LinkCredentialAsync(userId, assertion));
        Assert.That(ex.Message, Is.EqualTo("Credential for provider 'Google' is already linked to this user."));
        return Task.CompletedTask;
    }

    [Test]
    public async Task LoginAsyncWithFoundCredentialButNullUserShouldReturnFailed()
    {
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.Setup(p => p.SupportedType).Returns((ProviderType)"MOCK");
        providerMock.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(PasswordVerificationResult.Success));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<IUser>()))
            .Returns("key");

        var assertionMock = new Mock<IAuthenticationAssertion>();
        assertionMock.Setup(a => a.ProviderType).Returns((ProviderType)"MOCK");

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((IUser?)null);

        var service = new IdentityService(_repositoryMock.Object, [providerMock.Object], _secretProtectorMock.Object);

        var response = await service.LoginAsync("test@example.com", assertionMock.Object);

        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
    }

    [Test]
    public async Task LoginAsyncWithSaml2AssertionShouldReturnSuccess()
    {
        var providerKey = "saml-sub";
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = "saml@example.com" };
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.Saml2,
            ProviderName = "Okta",
            ProviderKey = providerKey
        };
        var assertion = new ExternalIdentityAssertion(ProviderType.Saml2, "Okta", providerKey, new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Saml2, "Okta", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Saml2, "Okta", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var response = await _identityService.LoginAsync("saml@example.com", assertion);

        Assert.That(response.Succeeded, Is.True);
    }

    [Test]
    public async Task LinkCredentialAsyncWithExternalProviderShouldProtectCredentialValue()
    {
        var userId = Guid.NewGuid();
        var type = ProviderType.Oidc;
        var providerName = "Google";
        var plainToken = "raw-token";
        var protectedToken = "protected(raw-token)";
        var assertion = new ExternalIdentityAssertion(type, providerName, "sub", new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, Email = "test@example.com" });

        await _identityService.LinkCredentialAsync(userId, assertion, plainToken);

        _repositoryMock.Verify(r => r.CreateCredentialAsync(It.Is<UserCredential>(c =>
            c.CredentialValue == protectedToken), It.IsAny<CancellationToken>()), Times.Once);
        _secretProtectorMock.Verify(s => s.Protect(plainToken), Times.Once);
    }

    [Test]
    public async Task LoginAsyncWithExternalProviderShouldUnprotectCredentialValue()
    {
        var email = "test@example.com";
        var providerKey = "sub-123";
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = email };
        var protectedToken = "protected(raw-token)";
        var plainToken = "raw-token";
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.Oidc,
            ProviderName = "Google",
            ProviderKey = providerKey,
            CredentialValue = protectedToken
        };
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", providerKey, new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, "Google", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Oidc, "Google", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        // Mock a provider to capture the credential passed to it
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.Setup(p => p.SupportedType).Returns(ProviderType.Oidc);
        providerMock.Setup(p => p.AuthenticateAsync(assertion, It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(PasswordVerificationResult.Success));
        providerMock.Setup(p => p.GetProviderKey(assertion, user)).Returns(providerKey);

        var service = new IdentityService(_repositoryMock.Object, [providerMock.Object], _secretProtectorMock.Object);

        await service.LoginAsync(email, assertion);

        providerMock.Verify(p => p.AuthenticateAsync(assertion, It.Is<UserCredential>(c => c.CredentialValue == plainToken), It.IsAny<CancellationToken>()), Times.Once);
        _secretProtectorMock.Verify(s => s.Unprotect(protectedToken), Times.Once);
    }

    [Test]
    public async Task LoginAsyncWithLocalProviderShouldNotUnprotectCredentialValue()
    {
        var email = "test@example.com";
        var password = "pass";
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = email };
        var hash = Convert.ToBase64String([0x02, 1, 2, 3]);
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.Local,
            ProviderName = ProviderType.Local.Value,
            ProviderKey = userId.ToString(),
            CredentialValue = hash
        };

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(email, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Local, ProviderType.Local.Value, userId.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        await _identityService.LoginAsync(email, new LocalPasswordAssertion(password));

        _secretProtectorMock.Verify(s => s.Unprotect(It.IsAny<string>()), Times.Never);
    }

    [Test]
    public async Task LoginAsyncWithExternalProviderUpdatingTokenShouldProtectNewToken()
    {
        var email = "test@example.com";
        var providerKey = "sub-123";
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = email };
        var oldTokenProtected = "protected(old-token)";
        var newTokenPlain = "new-token";
        var newTokenProtected = "protected(new-token)";
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.OAuth,
            ProviderName = "GitHub",
            ProviderKey = providerKey,
            CredentialValue = oldTokenProtected
        };
        var assertion = new ExternalIdentityAssertion(ProviderType.OAuth, "GitHub", providerKey, new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.OAuth, "GitHub", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.OAuth, "GitHub", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        // Mock a provider that wants to update the token
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.Setup(p => p.SupportedType).Returns(ProviderType.OAuth);
        providerMock.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(PasswordVerificationResult.Success, ShouldUpdateCredential: true, NewCredentialValue: newTokenPlain));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<IUser>())).Returns(providerKey);

        var service = new IdentityService(_repositoryMock.Object, [providerMock.Object], _secretProtectorMock.Object);

        await service.LoginAsync(email, assertion);

        _repositoryMock.Verify(r => r.UpdateCredentialAsync(It.Is<UserCredential>(c =>
            c.CredentialValue == newTokenProtected), It.IsAny<CancellationToken>()), Times.Once);
        _secretProtectorMock.Verify(s => s.Protect(newTokenPlain), Times.Once);
    }

    [Test]
    public async Task LoginAsyncWithExternalProviderAndMissingUserShouldStillCallUnprotect()
    {
        var email = "ghost@example.com";
        var providerKey = "sub-123";
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", providerKey, new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, "Google", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync((IUser?)null);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(It.IsAny<Guid>(), ProviderType.Oidc, "Google", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync((UserCredential?)null);

        await _identityService.LoginAsync(email, assertion);

        _secretProtectorMock.Verify(s => s.Unprotect("protected(DUMMY_PAYLOAD_TO_MAINTAIN_TIMING)"), Times.Once);
    }

    [Test]
    public async Task LoginAsyncWithExternalProviderAndMalformedCredentialShouldHandleException()
    {
        var email = "test@example.com";
        var providerKey = "sub-123";
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = email };
        var malformedToken = "not-protected";
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.Oidc,
            ProviderName = "Google",
            ProviderKey = providerKey,
            CredentialValue = malformedToken
        };
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", providerKey, new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, "Google", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Oidc, "Google", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        _secretProtectorMock.Setup(s => s.Unprotect(malformedToken))
            .Throws(new System.Security.Cryptography.CryptographicException());

        // Mock a provider to capture the credential passed to it
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.Setup(p => p.SupportedType).Returns(ProviderType.Oidc);
        providerMock.Setup(p => p.AuthenticateAsync(assertion, It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(PasswordVerificationResult.Success));
        providerMock.Setup(p => p.GetProviderKey(assertion, user)).Returns(providerKey);

        var service = new IdentityService(_repositoryMock.Object, [providerMock.Object], _secretProtectorMock.Object);

        var response = await service.LoginAsync(email, assertion);

        Assert.That(response.Succeeded, Is.False);
        providerMock.Verify(p => p.AuthenticateAsync(assertion, It.Is<UserCredential>(c => c.CredentialValue == null), It.IsAny<CancellationToken>()), Times.Once);
        Assert.That(credential.CredentialValue, Is.EqualTo(malformedToken));
    }

    [Test]
    public async Task LoginAsyncWithExternalProviderAndNullCredentialValueShouldReturnSuccess()
    {
        var email = "test@example.com";
        var providerKey = "sub-123";
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = email };
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.Oidc,
            ProviderName = "Google",
            ProviderKey = providerKey,
            CredentialValue = null
        };
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", providerKey, new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, "Google", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Oidc, "Google", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var response = await _identityService.LoginAsync(email, assertion);

        Assert.That(response.Succeeded, Is.True);
        Assert.That(credential.CredentialValue, Is.Null);
    }

    [Test]
    public async Task LoginAsyncWithUserNotFoundShouldStillCallGetCredentialForTimingProtection()
    {
        var email = "ghost@example.com";
        _repositoryMock.Setup(r => r.GetUserByEmailAsync(email, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((User?)null);

        await _identityService.LoginAsync(email, new LocalPasswordAssertion("pass"));

        _repositoryMock.Verify(r => r.GetCredentialForUserAsync(
            It.IsAny<Guid>(),
            ProviderType.Local,
            ProviderType.Local.Value,
            It.IsAny<string>(),
            It.IsAny<CancellationToken>()), Times.Once, "GetCredentialForUserAsync must be called even if user is not found to prevent timing attacks.");
    }
}
