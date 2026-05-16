using Ashlar.Identity;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.Providers.External;
using Ashlar.Identity.Providers.Local;
using Ashlar.Security.Encryption;
using Ashlar.Security.Hashing;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Tests.Identity;

internal sealed class IdentityServiceTests
{
    private Mock<IIdentityRepository> _repositoryMock;
    private Mock<ISecretProtector> _secretProtectorMock;
    private FakeTimeProvider _timeProvider;
    private FakePasswordHasher _fakeHasher;
    private FakePasswordHasher _oldHasher;
    private PasswordHasherSelector _hasherSelector;
    private IdentityService _identityService;

    [SetUp]
    public void SetUp()
    {
        _repositoryMock = new Mock<IIdentityRepository>();
        _secretProtectorMock = new Mock<ISecretProtector>();
        _timeProvider = new FakeTimeProvider();

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
            new OidcAuthenticationProvider("Google"),
            new OidcAuthenticationProvider("GitHub"),
            new OAuthAuthenticationProvider("GitHub"),
            new Saml2AuthenticationProvider("Okta")
        };

        var credentialService = new CredentialService(
            _repositoryMock.Object,
            _secretProtectorMock.Object,
            new NullTransactionProvider(),
            new CredentialServiceDependencies(TimeProvider: _timeProvider));
        _identityService = new IdentityService(_repositoryMock.Object, providers, credentialService, new NullTransactionProvider());
        // Clear constructor-time Protect() calls so Verify() in tests only inspects invocations triggered by LoginAsync.
        _secretProtectorMock.Invocations.Clear();
    }

    [Test]
    public void ConstructorShouldThrowOnNullRepository()
    {
        var credService = new Mock<ICredentialService>();
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new IdentityService(null!, [], credService.Object, new NullTransactionProvider()));
    }

    [Test]
    public void ConstructorShouldThrowOnNullProviders()
    {
        var credService = new Mock<ICredentialService>();
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new IdentityService(_repositoryMock.Object, (IEnumerable<IAuthenticationProvider>)null!, credService.Object, new NullTransactionProvider()));
    }

    [Test]
    public void ConstructorShouldThrowOnDuplicateProviderKey()
    {
        var credService = new Mock<ICredentialService>();
        var providers = new[]
        {
            new OidcAuthenticationProvider("Google"),
            new OidcAuthenticationProvider("Google")
        };

        Assert.Throws<ArgumentException>(() => _ = new IdentityService(_repositoryMock.Object, providers, credService.Object, new NullTransactionProvider()));
    }

    [Test]
    public void ConstructorShouldThrowOnNullCredentialService()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new IdentityService(_repositoryMock.Object, [], null!, new NullTransactionProvider()));
    }

    [Test]
    public void ConstructorShouldThrowOnNullTransactionProvider()
    {
        var credService = new Mock<ICredentialService>();
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new IdentityService(_repositoryMock.Object, [], credService.Object, null!));
    }

    [Test]
    public void ConstructorWithCollaboratorsShouldThrowOnNullCredentialService()
    {
        var providerRegistry = new Mock<IAuthenticationProviderRegistry>();
        var authenticationPipeline = new Mock<IAuthenticationPipeline>();

        Assert.Throws<ArgumentNullException>(() => _ = new IdentityService(
            _repositoryMock.Object,
            providerRegistry.Object,
            // ReSharper disable once NullableWarningSuppressionIsUsed
            null!,
            authenticationPipeline.Object,
            new NullTransactionProvider()));
    }

    [Test]
    public void ConstructorWithCollaboratorsShouldThrowOnNullProviderRegistry()
    {
        var credentialService = new Mock<ICredentialService>();
        var authenticationPipeline = new Mock<IAuthenticationPipeline>();

        Assert.Throws<ArgumentNullException>(() => _ = new IdentityService(
            _repositoryMock.Object,
            // ReSharper disable once NullableWarningSuppressionIsUsed
            null!,
            credentialService.Object,
            authenticationPipeline.Object,
            new NullTransactionProvider()));
    }

    [Test]
    public void ConstructorWithCollaboratorsShouldThrowOnNullAuthenticationPipeline()
    {
        var providerRegistry = new Mock<IAuthenticationProviderRegistry>();
        var credentialService = new Mock<ICredentialService>();

        Assert.Throws<ArgumentNullException>(() => _ = new IdentityService(
            _repositoryMock.Object,
            providerRegistry.Object,
            credentialService.Object,
            // ReSharper disable once NullableWarningSuppressionIsUsed
            (IAuthenticationPipeline)null!,
            new NullTransactionProvider()));
    }

    [Test]
    public void ConstructorWithCollaboratorsShouldThrowOnNullTransactionProvider()
    {
        var providerRegistry = new Mock<IAuthenticationProviderRegistry>();
        var credentialService = new Mock<ICredentialService>();
        var authenticationPipeline = new Mock<IAuthenticationPipeline>();

        Assert.Throws<ArgumentNullException>(() => _ = new IdentityService(
            _repositoryMock.Object,
            providerRegistry.Object,
            credentialService.Object,
            authenticationPipeline.Object,
            null!));
    }

    [Test]
    public async Task LoginAsyncShouldDelegateToAuthenticationPipeline()
    {
        var providerRegistry = new Mock<IAuthenticationProviderRegistry>();
        var credentialService = new Mock<ICredentialService>();
        var authenticationPipeline = new Mock<IAuthenticationPipeline>();
        var context = new AuthenticationContext("test@example.com");
        var assertion = new LocalPasswordAssertion("pass");
        using var cancellationTokenSource = new CancellationTokenSource();
        var expected = new AuthenticationResponse(false, Status: AuthenticationStatus.Failed);

        authenticationPipeline.Setup(p => p.LoginAsync(context, assertion, cancellationTokenSource.Token))
            .ReturnsAsync(expected);

        var service = new IdentityService(
            _repositoryMock.Object,
            providerRegistry.Object,
            credentialService.Object,
            authenticationPipeline.Object,
            new NullTransactionProvider());

        var response = await service.LoginAsync(context, assertion, cancellationTokenSource.Token);

        Assert.That(response, Is.SameAs(expected));
        authenticationPipeline.Verify(p => p.LoginAsync(context, assertion, cancellationTokenSource.Token), Times.Once);
    }

    [Test]
    public async Task LinkCredentialAsyncShouldResolveProvider()
    {
        var providerRegistry = new Mock<IAuthenticationProviderRegistry>();
        var credentialService = new Mock<ICredentialService>();
        var authenticationPipeline = new Mock<IAuthenticationPipeline>();
        var provider = new Mock<IAuthenticationProvider>();
        var providerObject = provider.Object;
        var assertion = new LocalPasswordAssertion("pass");
        var userId = Guid.NewGuid();

        providerRegistry.Setup(r => r.TryGetProvider(assertion, out providerObject))
            .Returns(true);

        var service = new IdentityService(
            _repositoryMock.Object,
            providerRegistry.Object,
            credentialService.Object,
            authenticationPipeline.Object,
            new NullTransactionProvider());

        await service.LinkCredentialAsync(userId, assertion, "pass");

        providerRegistry.Verify(r => r.TryGetProvider(assertion, out providerObject), Times.Once);
        credentialService.Verify(s => s.LinkCredentialAsync(userId, assertion, providerObject, "pass", It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);
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
            ProviderName = AuthenticationProviderKey.Local.Name,
            ProviderKey = userId.ToString(),
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            CredentialValue = Convert.ToBase64String(new byte[] { 0x02, 1, 2, 3 })
        };

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(email, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Local, AuthenticationProviderKey.Local.Name, userId.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var response = await _identityService.LoginAsync(new AuthenticationContext(email), new LocalPasswordAssertion(password));

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
            ProviderName = AuthenticationProviderKey.Local.Name,
            ProviderKey = userId.ToString(),
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            CredentialValue = Convert.ToBase64String(new byte[] { 0x02, 1, 2, 3 })
        };

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(email, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Local, AuthenticationProviderKey.Local.Name, userId.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        _fakeHasher.ShouldVerify = false;

        var response = await _identityService.LoginAsync(new AuthenticationContext(email), new LocalPasswordAssertion(password));

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
            ProviderKey = providerKey,
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
        };

        var claims = new Dictionary<string, string> { { "name", "Google User" } };
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", providerKey, claims);

        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, "Google", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Oidc, "Google", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var response = await _identityService.LoginAsync(new AuthenticationContext(email), assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.True);
            Assert.That(response.Claims, Is.EqualTo(claims));
        }
    }

    [Test]
    public async Task LoginAsyncWithExternalProviderShouldNotRequireContextEmail()
    {
        var providerName = "Google";
        var providerKey = "google-sub-123";
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = "google-user@example.com" };
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.Oidc,
            ProviderName = providerName,
            ProviderKey = providerKey,
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
        };

        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, providerName, providerKey, new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, providerName, providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Oidc, providerName, providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var response = await _identityService.LoginAsync(new AuthenticationContext(), assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.True);
            Assert.That(response.User, Is.EqualTo(user));
        }

        _repositoryMock.Verify(r => r.GetUserByEmailAsync(It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()), Times.Never);
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

        var response = await _identityService.LoginAsync(new AuthenticationContext(email), assertion);

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
            ProviderKey = providerKey,
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
        };
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, providerName, providerKey, new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, providerName, providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Oidc, providerName, providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        await _identityService.LoginAsync(new AuthenticationContext(email), assertion);

        _repositoryMock.Verify(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Oidc, providerName, providerKey, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task LinkCredentialAsyncWithExistingCredentialShouldFail()
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

        var result = await _identityService.LinkCredentialAsync(userId, new ExternalIdentityAssertion(type, providerName, providerKey, new Dictionary<string, string>()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureReason, Is.EqualTo("already_linked_to_self"));
        }
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

        _repositoryMock.Verify(r => r.CreateOrReplaceCredentialAsync(It.Is<UserCredential>(c =>
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
            ProviderName = AuthenticationProviderKey.Local.Name,
            ProviderKey = user.Id.ToString(),
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            CredentialValue = Convert.ToBase64String(new byte[] { 0x02, 1, 2, 3 })
        };

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(email, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Local, AuthenticationProviderKey.Local.Name, user.Id.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);
        _fakeHasher.ShouldVerify = true;

        var response = await _identityService.LoginAsync(new AuthenticationContext(email), new LocalPasswordAssertion("pass"));

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
            ProviderKey = providerKey,
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
        };
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, providerName, providerKey, new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, providerName, providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Oidc, providerName, providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var response = await _identityService.LoginAsync(new AuthenticationContext(email), assertion);

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
            ProviderName = AuthenticationProviderKey.Local.Name,
            ProviderKey = user.Id.ToString(),
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            CredentialValue = Convert.ToBase64String([0x01, 1, 2, 3])
        };

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(email, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Local, AuthenticationProviderKey.Local.Name, user.Id.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        _oldHasher.ShouldVerify = true;
        var expectedHash = Convert.ToBase64String(new byte[] { 0x02, 0, 0, 0 });

        var response = await _identityService.LoginAsync(new AuthenticationContext(email), new LocalPasswordAssertion("pass"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.True);
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.SuccessWithCredentialUpdate));
        }

        _repositoryMock.Verify(r => r.UpdateCredentialAsync(It.Is<UserCredential>(c =>
            c.Id == credential.Id &&
            c.CredentialValue == expectedHash), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task LinkCredentialAsyncWithLocalPasswordShouldHashPassword()
    {
        var userId = Guid.NewGuid();
        var password = "plain-password";
        var expectedHash = Convert.ToBase64String(new byte[] { 0x02, 0, 0, 0 });

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, Email = "test@example.com" });
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Local, AuthenticationProviderKey.Local.Name, It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((UserCredential?)null);

        await _identityService.LinkCredentialAsync(userId, new LocalPasswordAssertion(password), password);

        _repositoryMock.Verify(r => r.CreateOrReplaceCredentialAsync(It.Is<UserCredential>(c =>
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
    public async Task LinkCredentialAsyncWithAlreadyLinkedToAnotherUserShouldFail()
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

        var result = await _identityService.LinkCredentialAsync(userId, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureReason, Is.EqualTo("already_linked_to_other"));
        }
    }

    [Test]
    public async Task LinkCredentialAsyncWithLocalTypeShouldForceProviderNameToLocal()
    {
        var userId = Guid.NewGuid();
        var type = ProviderType.Local;
        var password = "password";

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, Email = "test@example.com" });
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, type, AuthenticationProviderKey.Local.Name, userId.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((UserCredential?)null);

        await _identityService.LinkCredentialAsync(userId, new LocalPasswordAssertion(password), password);

        _repositoryMock.Verify(r => r.CreateOrReplaceCredentialAsync(It.Is<UserCredential>(c =>
            c.ProviderName == AuthenticationProviderKey.Local.Name), It.IsAny<CancellationToken>()), Times.Once);
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
            ProviderKey = providerKey,
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
        };

        var claims = new Dictionary<string, string> { { "login", "octocat" } };
        var assertion = new ExternalIdentityAssertion(ProviderType.OAuth, "GitHub", providerKey, claims);

        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.OAuth, "GitHub", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.OAuth, "GitHub", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var response = await _identityService.LoginAsync(new AuthenticationContext(email), assertion);

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
            ProviderName = AuthenticationProviderKey.Local.Name,
            ProviderKey = user.Id.ToString(),
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            CredentialValue = Convert.ToBase64String([0x01, 1, 2, 3])
        };

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(email, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Local, AuthenticationProviderKey.Local.Name, user.Id.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);
        _repositoryMock.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("DB error"));

        _oldHasher.ShouldVerify = true;

        var response = await _identityService.LoginAsync(new AuthenticationContext(email), new LocalPasswordAssertion("pass"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.True);
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.SuccessWithCredentialUpdate));
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
        var provider = new AuthenticationProviderKey(ProviderType.Oidc, "Google");
        var providerKey = "sub-123";
        var user = new User { Id = Guid.NewGuid(), Email = "test@example.com" };
        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(provider.Type, provider.Name, providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var result = await _identityService.FindByProviderKeyAsync(provider, providerKey);

        Assert.That(result, Is.EqualTo(user));
    }

    [Test]
    public void FindByProviderKeyAsyncWithUninitializedProviderShouldThrow()
    {
        Assert.ThrowsAsync<ArgumentException>(() => _identityService.FindByProviderKeyAsync(default, "key"));
    }

    [Test]
    public void FindByProviderKeyAsyncWithNullOrWhitespaceProviderKeyShouldThrow()
    {
        var provider = new AuthenticationProviderKey(ProviderType.Oidc, "Google");
        using (Assert.EnterMultipleScope())
        {
            // ReSharper disable once NullableWarningSuppressionIsUsed
            Assert.ThrowsAsync<ArgumentNullException>(() => _identityService.FindByProviderKeyAsync(provider, null!));
            Assert.ThrowsAsync<ArgumentException>(() => _identityService.FindByProviderKeyAsync(provider, ""));
            Assert.ThrowsAsync<ArgumentException>(() => _identityService.FindByProviderKeyAsync(provider, " "));
        }
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
    public void CreateUserAsyncShouldRejectEmailWithLineBreaks()
    {
        var user = new User { Id = Guid.NewGuid(), Email = "test@example.com\r\nBcc: attacker@example.com" };

        Assert.ThrowsAsync<ArgumentException>(() => _identityService.CreateUserAsync(user));

        _repositoryMock.Verify(r => r.CreateUserAsync(It.IsAny<IUser>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task CreateUserAsyncShouldTrimEmailBeforePersisting()
    {
        var createdAt = new DateTimeOffset(2026, 5, 10, 12, 0, 0, TimeSpan.Zero);
        var updatedAt = createdAt.AddMinutes(1);
        var user = new AuditedUser
        {
            Id = Guid.NewGuid(),
            Email = " test@example.com ",
            Name = "Test User",
            IsActive = true,
            TenantId = Guid.NewGuid(),
            EmailVerifiedAt = createdAt,
            CreatedAt = createdAt,
            UpdatedAt = updatedAt
        };
        IUser? persistedUser = null;
        _repositoryMock
            .Setup(r => r.CreateUserAsync(It.IsAny<IUser>(), It.IsAny<CancellationToken>()))
            .Callback<IUser, CancellationToken>((u, _) => persistedUser = u)
            .Returns(Task.CompletedTask);

        var result = await _identityService.CreateUserAsync(user);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Email, Is.EqualTo("test@example.com"));
            Assert.That(persistedUser?.Email, Is.EqualTo("test@example.com"));
            Assert.That(persistedUser?.Name, Is.EqualTo(user.Name));
            Assert.That(persistedUser?.IsActive, Is.True);
            Assert.That((persistedUser as ITenantUser)?.TenantId, Is.EqualTo(user.TenantId));
            Assert.That(persistedUser?.EmailVerifiedAt, Is.EqualTo(user.EmailVerifiedAt));
            Assert.That((persistedUser as IHasAuditMetadata)?.CreatedAt, Is.EqualTo(createdAt));
            Assert.That((persistedUser as IHasAuditMetadata)?.UpdatedAt, Is.EqualTo(updatedAt));
        }

        ((IHasAuditMetadata)persistedUser!).UpdatedAt = updatedAt.AddMinutes(1);
        Assert.That(user.UpdatedAt, Is.EqualTo(updatedAt.AddMinutes(1)));
    }

    [Test]
    public async Task CreateUserAsyncShouldTrimEmailForNonTenantUserWithoutAuditMetadata()
    {
        var user = new BasicUser
        {
            Id = Guid.NewGuid(),
            Email = " basic@example.com ",
            IsActive = true
        };
        IUser? persistedUser = null;
        _repositoryMock
            .Setup(r => r.CreateUserAsync(It.IsAny<IUser>(), It.IsAny<CancellationToken>()))
            .Callback<IUser, CancellationToken>((u, _) => persistedUser = u)
            .Returns(Task.CompletedTask);

        await _identityService.CreateUserAsync(user);

        using (Assert.EnterMultipleScope())
        {
            Assert.That((persistedUser as ITenantUser)?.TenantId, Is.Null);
            Assert.That((persistedUser as IHasAuditMetadata)?.CreatedAt, Is.EqualTo(default(DateTimeOffset)));
            Assert.That((persistedUser as IHasAuditMetadata)?.UpdatedAt, Is.Null);
        }

        ((IHasAuditMetadata)persistedUser!).UpdatedAt = DateTimeOffset.UtcNow;
    }

    [Test]
    public void SupportedProviderKeysShouldReturnKeys()
    {
        var keys = _identityService.SupportedProviderKeys.ToList();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(keys, Contains.Item(AuthenticationProviderKey.Local));
            Assert.That(keys, Contains.Item(new AuthenticationProviderKey(ProviderType.Oidc, "Google")));
        }
    }

    [Test]
    public async Task LoginAsyncWithUnsupportedProviderShouldReturnFailed()
    {
        var assertionMock = new Mock<IAuthenticationAssertion>();
        assertionMock.Setup(a => a.ProviderIdentity).Returns(new AuthenticationProviderKey((ProviderType)"Unsupported", "Unsupported"));

        var response = await _identityService.LoginAsync(new AuthenticationContext("test@example.com"), assertionMock.Object);

        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
    }

    [Test]
    public async Task LinkCredentialAsyncWithNonExistentUserShouldFail()
    {
        var userId = Guid.NewGuid();
        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync((IUser?)null);

        var result = await _identityService.LinkCredentialAsync(userId, new LocalPasswordAssertion("pass"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureReason, Is.EqualTo("user_not_found"));
        }
    }

    [Test]
    public async Task LinkCredentialAsyncWithUnsupportedProviderShouldFail()
    {
        var userId = Guid.NewGuid();
        var assertionMock = new Mock<IAuthenticationAssertion>();
        assertionMock.Setup(a => a.ProviderIdentity).Returns(new AuthenticationProviderKey((ProviderType)"Unsupported", "Unsupported"));

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, Email = "test@example.com" });

        var result = await _identityService.LinkCredentialAsync(userId, assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureReason, Does.Contain("is not supported"));
        }
    }

    [Test]
    public async Task LinkCredentialAsyncWithSameUserAlreadyLinkedShouldFail()
    {
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = "test@example.com" };
        var assertion = new LocalPasswordAssertion("pass");

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Local, AuthenticationProviderKey.Local.Name, userId.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var result = await _identityService.LinkCredentialAsync(userId, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureReason, Is.EqualTo("already_linked_to_self"));
        }
    }

    [Test]
    public async Task LinkCredentialAsyncWithSameUserAlreadyLinkedExternalShouldFail()
    {
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = "test@example.com" };
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "sub", new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var result = await _identityService.LinkCredentialAsync(userId, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureReason, Is.EqualTo("already_linked_to_self"));
        }
    }

    [Test]
    public async Task LoginAsyncWithRehashNeededButNullCredentialShouldNotAttemptUpdate()
    {
        var user = new User { Id = Guid.NewGuid(), Email = "test@example.com" };
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey((ProviderType)"MOCK", "MOCK"));
        providerMock.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.SucceededWithCredentialUpdate, NewCredentialValue: "new-hash"));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<Guid>()))
            .Returns("key");
        providerMock.Setup(p => p.FindUserAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<AuthenticationContext>(), It.IsAny<IIdentityRepository>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var assertion = new ExternalIdentityAssertion((ProviderType)"MOCK", "MOCK", "key", new Dictionary<string, string>());

        var credentialService = new CredentialService(_repositoryMock.Object, _secretProtectorMock.Object, new NullTransactionProvider());
        var service = new IdentityService(_repositoryMock.Object, [providerMock.Object], credentialService, new NullTransactionProvider());
        // Clear constructor-time Protect() calls so Verify() in this test only inspects invocations triggered by LoginAsync.
        _secretProtectorMock.Invocations.Clear();

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, (ProviderType)"MOCK", "MOCK", "key", It.IsAny<CancellationToken>()))
            .ReturnsAsync((UserCredential?)null);

        var response = await service.LoginAsync(new AuthenticationContext("test@example.com"), assertion);

        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.SuccessWithCredentialUpdate));
        _repositoryMock.Verify(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
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
            ProviderName = AuthenticationProviderKey.Local.Name,
            ProviderKey = user.Id.ToString(),
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            CredentialValue = Convert.ToBase64String([0x01, 1, 2, 3]),
            LastUsedAt = DateTimeOffset.UtcNow
        };

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(email, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Local, AuthenticationProviderKey.Local.Name, user.Id.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        _oldHasher.ShouldVerify = true;
        // Mocking rehash needed but returning null for new value
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(AuthenticationProviderKey.Local);
        providerMock.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.SucceededWithCredentialUpdate, NewCredentialValue: null));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<Guid>())).Returns(user.Id.ToString());
        providerMock.Setup(p => p.FindUserAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<AuthenticationContext>(), It.IsAny<IIdentityRepository>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var credentialService = new CredentialService(_repositoryMock.Object, _secretProtectorMock.Object, new NullTransactionProvider());
        var service = new IdentityService(_repositoryMock.Object, [providerMock.Object], credentialService, new NullTransactionProvider());
        // Clear constructor-time Protect() calls so Verify() in this test only inspects invocations triggered by LoginAsync.
        _secretProtectorMock.Invocations.Clear();

        var response = await service.LoginAsync(new AuthenticationContext(email), new LocalPasswordAssertion("pass"));

        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.SuccessWithCredentialUpdate));
        _repositoryMock.Verify(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task LinkCredentialAsyncWithNullValueDoesNotEncryptCredential()
    {
        var userId = Guid.NewGuid();
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "sub", new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, Email = "test@example.com" });

        await _identityService.LinkCredentialAsync(userId, assertion);

        _repositoryMock.Verify(r => r.CreateOrReplaceCredentialAsync(It.Is<UserCredential>(c =>
            c.CredentialValue == null), It.IsAny<CancellationToken>()), Times.Once);

        _secretProtectorMock.Verify(s => s.Protect(It.IsAny<string>()), Times.Never);
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
            ProviderKey = "sub",
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            CredentialValue = "malformed"
        };
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "sub", new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(It.IsAny<ProviderType>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(It.IsAny<Guid>(), It.IsAny<ProviderType>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        _secretProtectorMock.Setup(s => s.Unprotect("malformed")).Throws<System.Security.Cryptography.CryptographicException>();

        var response = await _identityService.LoginAsync(new AuthenticationContext(email), assertion);

        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
    }

    [Test]
    public async Task LoginAsyncWithWhitespaceLocalEmailShouldFail()
    {
        var response = await _identityService.LoginAsync(new AuthenticationContext(" "), new LocalPasswordAssertion("pass"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
        }

        _repositoryMock.Verify(r => r.GetUserByEmailAsync(It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task LoginAsyncWithNullLocalEmailShouldFail()
    {
        var response = await _identityService.LoginAsync(new AuthenticationContext(), new LocalPasswordAssertion("pass"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
        }

        _repositoryMock.Verify(r => r.GetUserByEmailAsync(It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public void ExternalIdentityAssertionWithEmptyProviderNameShouldThrow()
    {
        Assert.Throws<ArgumentException>(() => _ = new ExternalIdentityAssertion(ProviderType.Oidc, "", "key", new Dictionary<string, string>()));
    }

    [Test]
    public void LoginAsyncWithNullContextShouldThrow()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.ThrowsAsync<ArgumentNullException>(() => _identityService.LoginAsync(null!, new LocalPasswordAssertion("pass")));
    }

    [Test]
    public async Task LinkCredentialAsyncWithProviderKeyDerivationFailureShouldFail()
    {
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = "test@example.com" };

        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey((ProviderType)"MOCK", "MOCK"));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<Guid>()))
            .Returns(string.Empty);

        var assertion = new ExternalIdentityAssertion((ProviderType)"MOCK", "MOCK", "key", new Dictionary<string, string>());

        var credentialService = new CredentialService(_repositoryMock.Object, _secretProtectorMock.Object, new NullTransactionProvider());
        var service = new IdentityService(_repositoryMock.Object, [providerMock.Object], credentialService, new NullTransactionProvider());
        // Clear constructor-time Protect() calls so Verify() in this test only inspects invocations triggered by LoginAsync.
        _secretProtectorMock.Invocations.Clear();

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var result = await service.LinkCredentialAsync(userId, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureReason, Is.EqualTo("invalid_provider_key"));
        }
    }

    [Test]
    public void LoginAsyncWithNullAssertionShouldThrow()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.ThrowsAsync<ArgumentNullException>(() => _identityService.LoginAsync(new AuthenticationContext("test@example.com"), null!));
    }

    [Test]
    public async Task LoginAsyncWithCredentialUpdateStatusButNullUserShouldReturnFailed()
    {
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey((ProviderType)"MOCK", "MOCK"));
        providerMock.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.SucceededWithCredentialUpdate));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<Guid>()))
            .Returns("key");

        var assertionMock = new Mock<IAuthenticationAssertion>();
        assertionMock.Setup(a => a.ProviderIdentity).Returns(new AuthenticationProviderKey((ProviderType)"MOCK", "MOCK"));

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((IUser?)null);

        var credentialService = new CredentialService(_repositoryMock.Object, _secretProtectorMock.Object, new NullTransactionProvider());
        var service = new IdentityService(_repositoryMock.Object, [providerMock.Object], credentialService, new NullTransactionProvider());
        // Clear constructor-time Protect() calls so Verify() in this test only inspects invocations triggered by LoginAsync.
        _secretProtectorMock.Invocations.Clear();

        var response = await service.LoginAsync(new AuthenticationContext("test@example.com"), assertionMock.Object);

        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
    }

    [Test]
    public async Task LinkCredentialAsyncWithExternalAssertionAlreadyLinkedToSameUserShouldFail()
    {
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = "test@example.com" };
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "sub", new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var result = await _identityService.LinkCredentialAsync(userId, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureReason, Is.EqualTo("already_linked_to_self"));
        }
    }

    [Test]
    public async Task LoginAsyncWithFoundCredentialButNullUserShouldReturnFailed()
    {
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey((ProviderType)"MOCK", "MOCK"));
        providerMock.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<Guid>()))
            .Returns("key");

        var assertionMock = new Mock<IAuthenticationAssertion>();
        assertionMock.Setup(a => a.ProviderIdentity).Returns(new AuthenticationProviderKey((ProviderType)"MOCK", "MOCK"));

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((IUser?)null);

        var credentialService = new CredentialService(_repositoryMock.Object, _secretProtectorMock.Object, new NullTransactionProvider());
        var service = new IdentityService(_repositoryMock.Object, [providerMock.Object], credentialService, new NullTransactionProvider());
        // Clear constructor-time Protect() calls so Verify() in this test only inspects invocations triggered by LoginAsync.
        _secretProtectorMock.Invocations.Clear();

        var response = await service.LoginAsync(new AuthenticationContext("test@example.com"), assertionMock.Object);

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
            ProviderKey = providerKey,
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
        };
        var assertion = new ExternalIdentityAssertion(ProviderType.Saml2, "Okta", providerKey, new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Saml2, "Okta", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Saml2, "Okta", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var response = await _identityService.LoginAsync(new AuthenticationContext("saml@example.com"), assertion);

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

        _repositoryMock.Verify(r => r.CreateOrReplaceCredentialAsync(It.Is<UserCredential>(c =>
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
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            CredentialValue = protectedToken
        };
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", providerKey, new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, "Google", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Oidc, "Google", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        // Mock a provider to capture the credential passed to it
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);

        string? capturedCredentialValue = null;
        providerMock.Setup(p => p.AuthenticateAsync(assertion, It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .Callback<IAuthenticationAssertion, UserCredential, CancellationToken>((_, c, _) => capturedCredentialValue = c.CredentialValue)
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded));

        providerMock.Setup(p => p.GetProviderKey(assertion, user.Id)).Returns(providerKey);
        providerMock.Setup(p => p.FindUserAsync(assertion, It.IsAny<AuthenticationContext>(), It.IsAny<IIdentityRepository>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var credentialService = new CredentialService(_repositoryMock.Object, _secretProtectorMock.Object, new NullTransactionProvider());
        var service = new IdentityService(_repositoryMock.Object, [providerMock.Object], credentialService, new NullTransactionProvider());
        // Clear constructor-time Protect() calls so Verify() in this test only inspects invocations triggered by LoginAsync.
        _secretProtectorMock.Invocations.Clear();
        await service.LoginAsync(new AuthenticationContext(email), assertion);

        Assert.That(capturedCredentialValue, Is.EqualTo(plainToken));
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
            ProviderName = AuthenticationProviderKey.Local.Name,
            ProviderKey = userId.ToString(),
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            CredentialValue = hash
        };

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(email, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Local, AuthenticationProviderKey.Local.Name, userId.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        await _identityService.LoginAsync(new AuthenticationContext(email), new LocalPasswordAssertion(password));

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
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            CredentialValue = oldTokenProtected
        };
        var assertion = new ExternalIdentityAssertion(ProviderType.OAuth, "GitHub", providerKey, new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.OAuth, "GitHub", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.OAuth, "GitHub", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        // Mock a provider that wants to update the token
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.OAuth, "GitHub"));
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);
        providerMock.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.SucceededWithCredentialUpdate, NewCredentialValue: newTokenPlain));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<Guid>())).Returns(providerKey);
        providerMock.Setup(p => p.FindUserAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<AuthenticationContext>(), It.IsAny<IIdentityRepository>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var credentialService = new CredentialService(_repositoryMock.Object, _secretProtectorMock.Object, new NullTransactionProvider());
        var service = new IdentityService(_repositoryMock.Object, [providerMock.Object], credentialService, new NullTransactionProvider());
        // Clear constructor-time Protect() calls so Verify() in this test only inspects invocations triggered by LoginAsync.
        _secretProtectorMock.Invocations.Clear();
        await service.LoginAsync(new AuthenticationContext(email), assertion);

        _repositoryMock.Verify(r => r.UpdateCredentialAsync(It.Is<UserCredential>(c =>
            c.CredentialValue == newTokenProtected), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);
        _secretProtectorMock.Verify(s => s.Protect(newTokenPlain), Times.Once);
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
            ProviderKey = "sub",
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            CredentialValue = null
        };
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "sub", new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(It.IsAny<ProviderType>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(It.IsAny<Guid>(), It.IsAny<ProviderType>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var dummyValue = _secretProtectorMock.Object.Protect("DUMMY_PAYLOAD_TO_MAINTAIN_TIMING");
        _secretProtectorMock.Setup(s => s.Unprotect(dummyValue)).Throws<System.Security.Cryptography.CryptographicException>();

        var response = await _identityService.LoginAsync(new AuthenticationContext(email), assertion);

        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Success));
    }

    [Test]
    public async Task LoginAsyncWithExternalProviderAndMissingUserAndDummyUnprotectFailureShouldStillReturnFailed()
    {
        var email = "ghost@example.com";
        var providerKey = "sub-123";
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", providerKey, new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, "Google", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync((IUser?)null);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(It.IsAny<Guid>(), ProviderType.Oidc, "Google", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync((UserCredential?)null);

        // Fail unprotection for the dummy value
        var dummyValue = _secretProtectorMock.Object.Protect("DUMMY_PAYLOAD_TO_MAINTAIN_TIMING");
        _secretProtectorMock.Setup(s => s.Unprotect(dummyValue))
            .Throws<System.Security.Cryptography.CryptographicException>();

        var response = await _identityService.LoginAsync(new AuthenticationContext(email), assertion);

        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
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

        await _identityService.LoginAsync(new AuthenticationContext(email), assertion);

        _secretProtectorMock.Verify(s => s.Unprotect(It.IsAny<string>()), Times.Once);
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
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
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
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);
        providerMock.Setup(p => p.AuthenticateAsync(assertion, It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded));
        providerMock.Setup(p => p.GetProviderKey(assertion, user.Id)).Returns(providerKey);
        providerMock.Setup(p => p.FindUserAsync(assertion, It.IsAny<AuthenticationContext>(), It.IsAny<IIdentityRepository>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var credentialService = new CredentialService(_repositoryMock.Object, _secretProtectorMock.Object, new NullTransactionProvider());
        var service = new IdentityService(_repositoryMock.Object, [providerMock.Object], credentialService, new NullTransactionProvider());
        // Clear constructor-time Protect() calls so Verify() in this test only inspects invocations triggered by LoginAsync.
        _secretProtectorMock.Invocations.Clear();

        var response = await service.LoginAsync(new AuthenticationContext(email), assertion);

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
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            CredentialValue = null
        };
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", providerKey, new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, "Google", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Oidc, "Google", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);
        providerMock.Setup(p => p.AuthenticateAsync(assertion, It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded));
        providerMock.Setup(p => p.GetProviderKey(assertion, user.Id)).Returns(providerKey);
        providerMock.Setup(p => p.FindUserAsync(assertion, It.IsAny<AuthenticationContext>(), It.IsAny<IIdentityRepository>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var credentialService = new CredentialService(_repositoryMock.Object, _secretProtectorMock.Object, new NullTransactionProvider());
        var service = new IdentityService(_repositoryMock.Object, [providerMock.Object], credentialService, new NullTransactionProvider());
        // Clear constructor-time Protect() calls so Verify() in this test only inspects invocations triggered by LoginAsync.
        _secretProtectorMock.Invocations.Clear();

        var response = await service.LoginAsync(new AuthenticationContext(email), assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.True);
            providerMock.Verify(p => p.AuthenticateAsync(assertion, It.Is<UserCredential>(c => c.CredentialValue == null), It.IsAny<CancellationToken>()), Times.Once);
        }
    }

    [Test]
    public async Task LoginAsyncWithUserNotFoundShouldStillCallGetCredentialForTimingProtection()
    {
        var email = "ghost@example.com";
        _repositoryMock.Setup(r => r.GetUserByEmailAsync(email, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((User?)null);

        await _identityService.LoginAsync(new AuthenticationContext(email), new LocalPasswordAssertion("pass"));

        _repositoryMock.Verify(r => r.GetCredentialForUserAsync(
            It.IsAny<Guid>(),
            ProviderType.Local,
            AuthenticationProviderKey.Local.Name,
            It.IsAny<string>(),
            It.IsAny<CancellationToken>()), Times.Once, "GetCredentialForUserAsync must be called even if user is not found to prevent timing attacks.");
    }

    [Test]
    public async Task LoginAsyncWithUpdateCredentialFailureShouldStillReturnSuccess()
    {
        var email = "test@example.com";
        var user = new User { Id = Guid.NewGuid(), Email = email };
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.Local,
            ProviderName = AuthenticationProviderKey.Local.Name,
            ProviderKey = user.Id.ToString(),
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            CredentialValue = Convert.ToBase64String([0x01, 1, 2, 3])
        };

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(email, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Local, AuthenticationProviderKey.Local.Name, user.Id.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);
        _repositoryMock.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("Database failure"));

        _oldHasher.ShouldVerify = true;

        var response = await _identityService.LoginAsync(new AuthenticationContext(email), new LocalPasswordAssertion("pass"));

        Assert.That(response.Succeeded, Is.True);
        _repositoryMock.Verify(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task LoginAsyncWithRehashUpdateConflictShouldStillReturnSuccessWithCredentialUpdate()
    {
        var email = "test@example.com";
        var user = new User { Id = Guid.NewGuid(), Email = email };
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.Local,
            ProviderName = AuthenticationProviderKey.Local.Name,
            ProviderKey = user.Id.ToString(),
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            CredentialValue = Convert.ToBase64String([0x01, 1, 2, 3])
        };

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(email, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Local, AuthenticationProviderKey.Local.Name, user.Id.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);
        _repositoryMock.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), "v1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        _oldHasher.ShouldVerify = true;

        var response = await _identityService.LoginAsync(new AuthenticationContext(email), new LocalPasswordAssertion("pass"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.True);
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.SuccessWithCredentialUpdate));
        }
    }

    [Test]
    public async Task LoginAsyncWithLastUsedAtUpdateConflictShouldStillReturnSuccess()
    {
        var email = "test@example.com";
        var user = new User { Id = Guid.NewGuid(), Email = email };
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.Local,
            ProviderName = AuthenticationProviderKey.Local.Name,
            ProviderKey = user.Id.ToString(),
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            CredentialValue = Convert.ToBase64String([0x02, 1, 2, 3])
        };

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(email, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Local, AuthenticationProviderKey.Local.Name, user.Id.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);
        _repositoryMock.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), "v1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        var response = await _identityService.LoginAsync(new AuthenticationContext(email), new LocalPasswordAssertion("pass"));

        Assert.That(response.Succeeded, Is.True);
    }

    [Test]
    public async Task LoginAsyncShouldUpdateLastUsedAt()
    {
        var email = "test@example.com";
        var user = new User { Id = Guid.NewGuid(), Email = email };
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.Local,
            ProviderName = AuthenticationProviderKey.Local.Name,
            ProviderKey = user.Id.ToString(),
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            CredentialValue = Convert.ToBase64String([0x02, 1, 2, 3])
        };

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(email, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Local, AuthenticationProviderKey.Local.Name, user.Id.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var startTime = _timeProvider.GetUtcNow();
        await _identityService.LoginAsync(new AuthenticationContext(email), new LocalPasswordAssertion("pass"));
        var endTime = _timeProvider.GetUtcNow();

        _repositoryMock.Verify(r => r.UpdateCredentialAsync(It.Is<UserCredential>(c =>
            c.LastUsedAt >= startTime && c.LastUsedAt <= endTime), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task LoginAsyncShouldPreserveAndUpdateMetadata()
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
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            CredentialValue = "protected(token)",
            Metadata = "original-metadata"
        };
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "sub", new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);
        providerMock.Setup(p => p.AuthenticateAsync(assertion, It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded, NewMetadata: "new-metadata"));
        providerMock.Setup(p => p.GetProviderKey(assertion, user.Id)).Returns("sub");
        providerMock.Setup(p => p.FindUserAsync(assertion, It.IsAny<AuthenticationContext>(), It.IsAny<IIdentityRepository>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var credentialService = new CredentialService(_repositoryMock.Object, _secretProtectorMock.Object, new NullTransactionProvider());
        var service = new IdentityService(_repositoryMock.Object, [providerMock.Object], credentialService, new NullTransactionProvider());
        // Clear constructor-time Protect() calls so Verify() in this test only inspects invocations triggered by LoginAsync.
        _secretProtectorMock.Invocations.Clear();
        await service.LoginAsync(new AuthenticationContext(email), assertion);

        _repositoryMock.Verify(r => r.UpdateCredentialAsync(It.Is<UserCredential>(c =>
            c.Metadata == "new-metadata" && c.CredentialValue == "protected(token)"), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task LoginAsyncShouldConsumeCredentialAtomicallyIfRequested()
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
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            CredentialValue = "protected(token)"
        };
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "sub", new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);
        providerMock.Setup(p => p.AuthenticateAsync(assertion, It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded, IsCredentialConsumed: true));
        providerMock.Setup(p => p.GetProviderKey(assertion, user.Id)).Returns("sub");
        providerMock.Setup(p => p.FindUserAsync(assertion, It.IsAny<AuthenticationContext>(), It.IsAny<IIdentityRepository>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.ConsumeCredentialAsync(credential.Id, "v1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var credentialService = new CredentialService(_repositoryMock.Object, _secretProtectorMock.Object, new NullTransactionProvider());
        var service = new IdentityService(_repositoryMock.Object, [providerMock.Object], credentialService, new NullTransactionProvider());
        // Clear constructor-time Protect() calls so Verify() in this test only inspects invocations triggered by LoginAsync.
        _secretProtectorMock.Invocations.Clear();
        var response = await service.LoginAsync(new AuthenticationContext(email), assertion);

        Assert.That(response.Succeeded, Is.True);
        _repositoryMock.Verify(r => r.ConsumeCredentialAsync(credential.Id, "v1", It.IsAny<CancellationToken>()), Times.Once);
        _repositoryMock.Verify(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task LoginAsyncShouldPreserveExistingMetadataWhenOnlyLastUsedAtUpdates()
    {
        var email = "test@example.com";
        var user = new User { Id = Guid.NewGuid(), Email = email };
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.Local,
            ProviderName = AuthenticationProviderKey.Local.Name,
            ProviderKey = user.Id.ToString(),
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            CredentialValue = Convert.ToBase64String([0x02, 1, 2, 3]),
            Metadata = "important-data"
        };

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(email, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Local, AuthenticationProviderKey.Local.Name, user.Id.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        await _identityService.LoginAsync(new AuthenticationContext(email), new LocalPasswordAssertion("pass"));

        _repositoryMock.Verify(r => r.UpdateCredentialAsync(It.Is<UserCredential>(c =>
            c.Metadata == "important-data" && c.LastUsedAt != null), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task LoginAsyncShouldUpdateMetadataWhenCredentialValueIsNull()
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
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            CredentialValue = null, // Credential value is null
            Metadata = "old-metadata"
        };
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "sub", new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);
        providerMock.Setup(p => p.AuthenticateAsync(assertion, It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded, NewMetadata: "new-metadata"));
        providerMock.Setup(p => p.GetProviderKey(assertion, user.Id)).Returns("sub");
        providerMock.Setup(p => p.FindUserAsync(assertion, It.IsAny<AuthenticationContext>(), It.IsAny<IIdentityRepository>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var credentialService = new CredentialService(_repositoryMock.Object, _secretProtectorMock.Object, new NullTransactionProvider());
        var service = new IdentityService(_repositoryMock.Object, [providerMock.Object], credentialService, new NullTransactionProvider());
        // Clear constructor-time Protect() calls so Verify() in this test only inspects invocations triggered by LoginAsync.
        _secretProtectorMock.Invocations.Clear();
        await service.LoginAsync(new AuthenticationContext(email), assertion);

        _repositoryMock.Verify(r => r.UpdateCredentialAsync(It.Is<UserCredential>(c =>
            c.Metadata == "new-metadata" && c.CredentialValue == null), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task LoginAsyncShouldReturnFailedWhenAtomicConsumeReturnsFalse()
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
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            CredentialValue = "token"
        };
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "sub", new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);
        providerMock.Setup(p => p.AuthenticateAsync(assertion, It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded, IsCredentialConsumed: true));
        providerMock.Setup(p => p.GetProviderKey(assertion, user.Id)).Returns("sub");
        providerMock.Setup(p => p.FindUserAsync(assertion, It.IsAny<AuthenticationContext>(), It.IsAny<IIdentityRepository>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _repositoryMock.Setup(r => r.ConsumeCredentialAsync(credential.Id, "v1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        var credentialService = new CredentialService(_repositoryMock.Object, _secretProtectorMock.Object, new NullTransactionProvider());
        var service = new IdentityService(_repositoryMock.Object, [providerMock.Object], credentialService, new NullTransactionProvider());
        // Clear constructor-time Protect() calls so Verify() in this test only inspects invocations triggered by LoginAsync.
        _secretProtectorMock.Invocations.Clear();

        var response = await service.LoginAsync(new AuthenticationContext(email), assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
        }
        _repositoryMock.Verify(r => r.ConsumeCredentialAsync(credential.Id, "v1", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public Task LoginAsyncShouldThrowIfCredentialConsumptionIsCancelled()
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
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            CredentialValue = "token"
        };
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "sub", new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);
        providerMock.Setup(p => p.AuthenticateAsync(assertion, It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded, IsCredentialConsumed: true));
        providerMock.Setup(p => p.GetProviderKey(assertion, user.Id)).Returns("sub");
        providerMock.Setup(p => p.FindUserAsync(assertion, It.IsAny<AuthenticationContext>(), It.IsAny<IIdentityRepository>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _repositoryMock.Setup(r => r.ConsumeCredentialAsync(credential.Id, "v1", It.IsAny<CancellationToken>()))
            .ThrowsAsync(new OperationCanceledException());

        var credentialService = new CredentialService(_repositoryMock.Object, _secretProtectorMock.Object, new NullTransactionProvider());
        var service = new IdentityService(_repositoryMock.Object, [providerMock.Object], credentialService, new NullTransactionProvider());
        // Clear constructor-time Protect() calls so Verify() in this test only inspects invocations triggered by LoginAsync.
        _secretProtectorMock.Invocations.Clear();

        Assert.ThrowsAsync<OperationCanceledException>(async () => await service.LoginAsync(new AuthenticationContext(email), assertion));
        return Task.CompletedTask;
    }

    [Test]
    public async Task LoginAsyncShouldNotReProtectWhenOnlyMetadataChanges()
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
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            CredentialValue = "protected(existing)"
        };
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "sub", new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);

        // Metadata updated, but no new credential value
        providerMock.Setup(p => p.AuthenticateAsync(assertion, It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded, NewMetadata: "new-meta"));
        providerMock.Setup(p => p.GetProviderKey(assertion, user.Id)).Returns("sub");
        providerMock.Setup(p => p.FindUserAsync(assertion, It.IsAny<AuthenticationContext>(), It.IsAny<IIdentityRepository>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var credentialService = new CredentialService(_repositoryMock.Object, _secretProtectorMock.Object, new NullTransactionProvider());
        var service = new IdentityService(_repositoryMock.Object, [providerMock.Object], credentialService, new NullTransactionProvider());
        // Clear constructor-time Protect() calls so Verify() in this test only inspects invocations triggered by LoginAsync.
        _secretProtectorMock.Invocations.Clear();
        await service.LoginAsync(new AuthenticationContext(email), assertion);

        _repositoryMock.Verify(r => r.UpdateCredentialAsync(It.Is<UserCredential>(c =>
            c.CredentialValue == "protected(existing)" && c.Metadata == "new-meta"), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);

        _secretProtectorMock.Verify(s => s.Protect(It.IsAny<string>()), Times.Never);
    }

    [Test]
    public async Task LoginAsyncShouldPreserveOldCredentialValueWhenNewValueIsNullAndUpdateRequested()
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
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            CredentialValue = "protected(old-value)"
        };
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "sub", new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);

        // Return a credential update status, but NewCredentialValue = null
        providerMock.Setup(p => p.AuthenticateAsync(assertion, It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.SucceededWithCredentialUpdate, NewCredentialValue: null));
        providerMock.Setup(p => p.GetProviderKey(assertion, user.Id)).Returns("sub");
        providerMock.Setup(p => p.FindUserAsync(assertion, It.IsAny<AuthenticationContext>(), It.IsAny<IIdentityRepository>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var credentialService = new CredentialService(_repositoryMock.Object, _secretProtectorMock.Object, new NullTransactionProvider());
        var service = new IdentityService(_repositoryMock.Object, [providerMock.Object], credentialService, new NullTransactionProvider());
        // Clear constructor-time Protect() calls so Verify() in this test only inspects invocations triggered by LoginAsync.
        _secretProtectorMock.Invocations.Clear();
        await service.LoginAsync(new AuthenticationContext(email), assertion);

        // Verify that we updated the credential, but with the OLD value (preserved)
        _repositoryMock.Verify(r => r.UpdateCredentialAsync(It.Is<UserCredential>(c =>
            c.CredentialValue == "protected(old-value)"), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);

        // Ensure Protect was not called for this update (excluding dummy init)
        _secretProtectorMock.Verify(s => s.Protect(It.IsAny<string>()), Times.Never);
    }

    [Test]
    public async Task LoginAsyncShouldUpdateMetadataWhenExplicitlyEmptyAndCurrentIsNull()
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
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            CredentialValue = "protected(token)",
            Metadata = null // Currently null
        };
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "sub", new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);
        providerMock.Setup(p => p.AuthenticateAsync(assertion, It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded, NewMetadata: string.Empty)); // Explicitly empty
        providerMock.Setup(p => p.GetProviderKey(assertion, user.Id)).Returns("sub");
        providerMock.Setup(p => p.FindUserAsync(assertion, It.IsAny<AuthenticationContext>(), It.IsAny<IIdentityRepository>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var credentialService = new CredentialService(_repositoryMock.Object, _secretProtectorMock.Object, new NullTransactionProvider());
        var service = new IdentityService(_repositoryMock.Object, [providerMock.Object], credentialService, new NullTransactionProvider());
        _secretProtectorMock.Invocations.Clear();
        await service.LoginAsync(new AuthenticationContext(email), assertion);

        // Verify update occurred because "" != null
        _repositoryMock.Verify(r => r.UpdateCredentialAsync(It.Is<UserCredential>(c =>
            c.Metadata == string.Empty), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task LoginAsyncShouldNotUpdateMetadataWhenProviderReturnsNull()
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
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            CredentialValue = "protected(token)",
            Metadata = "some-metadata",
            LastUsedAt = DateTimeOffset.UtcNow // Set to now to avoid LastUsedAt update triggering the write
        };
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "sub", new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);
        providerMock.Setup(p => p.AuthenticateAsync(assertion, It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded, NewMetadata: null)); // No change
        providerMock.Setup(p => p.GetProviderKey(assertion, user.Id)).Returns("sub");
        providerMock.Setup(p => p.FindUserAsync(assertion, It.IsAny<AuthenticationContext>(), It.IsAny<IIdentityRepository>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var credentialService = new CredentialService(_repositoryMock.Object, _secretProtectorMock.Object, new NullTransactionProvider());
        var service = new IdentityService(_repositoryMock.Object, [providerMock.Object], credentialService, new NullTransactionProvider());
        _secretProtectorMock.Invocations.Clear();
        await service.LoginAsync(new AuthenticationContext(email), assertion);

        // Verify NO update occurred because NewMetadata is null
        _repositoryMock.Verify(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task LoginAsyncShouldNotUpdateCredentialIfLastUsedAtIsRecent()
    {
        var email = "test@example.com";
        var user = new User { Id = Guid.NewGuid(), Email = email };
        var lastUsedAt = DateTimeOffset.UtcNow.AddSeconds(-30); // 30 seconds ago
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.Local,
            ProviderName = AuthenticationProviderKey.Local.Name,
            ProviderKey = user.Id.ToString(),
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            CredentialValue = Convert.ToBase64String([0x02, 1, 2, 3]),
            LastUsedAt = lastUsedAt
        };

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(email, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Local, AuthenticationProviderKey.Local.Name, user.Id.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        await _identityService.LoginAsync(new AuthenticationContext(email), new LocalPasswordAssertion("pass"));

        // Verify UpdateCredentialAsync was NEVER called because 30 seconds < 1 minute threshold
        _repositoryMock.Verify(r => r.UpdateCredentialAsync(It.Is<UserCredential>(c => c.Id == credential.Id), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task LoginAsyncShouldGenerateRandomProviderKeyIfProviderReturnsNullOrEmpty()
    {
        var email = "test@example.com";
        var user = new User { Id = Guid.NewGuid(), Email = email };

        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey((ProviderType)"MOCK", "MOCK"));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<Guid>())).Returns(string.Empty); // Return empty
        providerMock.Setup(p => p.FindUserAsync(It.IsAny<IAuthenticationAssertion>(), It.Is<AuthenticationContext>(c => c.Email == email), _repositoryMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        providerMock.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded));

        var assertion = new ExternalIdentityAssertion((ProviderType)"MOCK", "MOCK", "key", new Dictionary<string, string>());

        var credentialService = new CredentialService(_repositoryMock.Object, _secretProtectorMock.Object, new NullTransactionProvider());
        var service = new IdentityService(_repositoryMock.Object, [providerMock.Object], credentialService, new NullTransactionProvider());
        // Clear constructor-time Protect() calls so Verify() in this test only inspects invocations triggered by LoginAsync.
        _secretProtectorMock.Invocations.Clear();

        await service.LoginAsync(new AuthenticationContext(email), assertion);

        // Verify that GetCredentialForUserAsync was called with a generated key (not the empty one returned by provider)
        _repositoryMock.Verify(r => r.GetCredentialForUserAsync(
            user.Id,
            (ProviderType)"MOCK",
            "MOCK",
            It.Is<string>(key => !string.IsNullOrEmpty(key)),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task LoginAsyncWithSuccessWithCredentialUpdateShouldUpdateRepository()
    {
        var email = "rehash@example.com";
        var user = new User { Id = Guid.NewGuid(), Email = email };
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.Local,
            ProviderName = AuthenticationProviderKey.Local.Name,
            ProviderKey = user.Id.ToString(),
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            CredentialValue = "old-hash"
        };

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(email, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Local, AuthenticationProviderKey.Local.Name, user.Id.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(AuthenticationProviderKey.Local);
        providerMock.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.SucceededWithCredentialUpdate, NewCredentialValue: "new-hash"));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<Guid>())).Returns(user.Id.ToString());
        providerMock.Setup(p => p.FindUserAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<AuthenticationContext>(), It.IsAny<IIdentityRepository>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var credentialService = new CredentialService(_repositoryMock.Object, _secretProtectorMock.Object, new NullTransactionProvider());
        var service = new IdentityService(_repositoryMock.Object, [providerMock.Object], credentialService, new NullTransactionProvider());
        _secretProtectorMock.Invocations.Clear();

        var response = await service.LoginAsync(new AuthenticationContext(email), new LocalPasswordAssertion("pass"));

        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.SuccessWithCredentialUpdate));
        _repositoryMock.Verify(r => r.UpdateCredentialAsync(It.Is<UserCredential>(c => c.CredentialValue == "new-hash"), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task LoginAsyncWithRequiredUpdateFailureShouldReturnFailed()
    {
        var email = "test@example.com";
        var user = new User { Id = Guid.NewGuid(), Email = email };
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.Local,
            ProviderName = "LOCAL",
            ProviderKey = user.Id.ToString(),
            Version = "v1",
            CredentialValue = "old",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active
        };

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(email, It.IsAny<Guid?>(), It.IsAny<CancellationToken>())).ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Local, "LOCAL", It.IsAny<string>(), It.IsAny<CancellationToken>())).ReturnsAsync(credential);

        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Local, "LOCAL"));
        providerMock.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded, CredentialUpdateRequirement: CredentialUpdateRequirement.Required, NewCredentialValue: "new"));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<Guid>())).Returns(user.Id.ToString());
        providerMock.Setup(p => p.FindUserAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<AuthenticationContext>(), It.IsAny<IIdentityRepository>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _repositoryMock.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("Update failed"));

        var credentialService = new CredentialService(_repositoryMock.Object, _secretProtectorMock.Object, new NullTransactionProvider());
        var service = new IdentityService(_repositoryMock.Object, [providerMock.Object], credentialService, new NullTransactionProvider());

        var response = await service.LoginAsync(new AuthenticationContext(email), new LocalPasswordAssertion("pass"));

        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
    }

    [Test]
    public async Task LoginAsyncWithConsumptionFailureShouldReturnFailed()
    {
        var email = "test@example.com";
        var user = new User { Id = Guid.NewGuid(), Email = email };
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.Oidc,
            ProviderName = "Google",
            ProviderKey = "key",
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active
        };

        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, "Google", "key", It.IsAny<CancellationToken>())).ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Oidc, "Google", "key", It.IsAny<CancellationToken>())).ReturnsAsync(credential);

        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded, IsCredentialConsumed: true));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<Guid>())).Returns("key");
        providerMock.Setup(p => p.FindUserAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<AuthenticationContext>(), It.IsAny<IIdentityRepository>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _repositoryMock.Setup(r => r.ConsumeCredentialAsync(credential.Id, "v1", It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("Consume failed"));

        var credentialService = new CredentialService(_repositoryMock.Object, _secretProtectorMock.Object, new NullTransactionProvider());
        var service = new IdentityService(_repositoryMock.Object, [providerMock.Object], credentialService, new NullTransactionProvider());

        var response = await service.LoginAsync(new AuthenticationContext(email), new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "key", new Dictionary<string, string>()));

        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
    }

    private sealed class AuditedUser : ITenantUser, IHasAuditMetadata
    {
        public required Guid Id { get; init; }
        public required string Email { get; set; }
        public string? Name { get; set; }
        public bool IsActive { get; set; }
        public Guid? TenantId { get; set; }
        public DateTimeOffset? EmailVerifiedAt { get; set; }
        public DateTimeOffset CreatedAt { get; init; }
        public DateTimeOffset? UpdatedAt { get; set; }
    }

    private sealed class BasicUser : IUser
    {
        public required Guid Id { get; init; }
        public required string Email { get; init; }
        public string? Name { get; init; }
        public bool IsActive { get; init; }
        public DateTimeOffset? EmailVerifiedAt { get; init; }
    }
}
