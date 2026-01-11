using Ashlar.Identity;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.Providers;
using Ashlar.Security.Hashing;
using Moq;

namespace Ashlar.Tests.Identity;

public class IdentityServiceTests
{
    private Mock<IIdentityRepository> _repositoryMock;
    private FakePasswordHasher _fakeHasher;
    private FakePasswordHasher _oldHasher;
    private PasswordHasherSelector _hasherSelector;
    private IdentityService _identityService;

    [SetUp]
    public void SetUp()
    {
        _repositoryMock = new Mock<IIdentityRepository>();
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

        _identityService = new IdentityService(_repositoryMock.Object, providers);
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
