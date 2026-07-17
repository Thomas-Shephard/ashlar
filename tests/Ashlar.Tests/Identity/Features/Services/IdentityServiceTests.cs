using Ashlar.Auditing;
using Ashlar.Identity.Providers.External;
using Ashlar.Identity.Providers.Local;
using Ashlar.Security.Encryption;
using Ashlar.Security.Hashing;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Tests.Identity.Features.Services;

internal sealed class IdentityServiceTests
{
    private Mock<IUserRepository> _repositoryMock = null!;
    private Mock<ICredentialRepository> _credentialRepositoryMock = null!;
    private Mock<ISecretProtector> _secretProtectorMock = null!;
    private FakeTimeProvider _timeProvider = null!;
    private FakePasswordHasher _fakeHasher = null!;
    private FakePasswordHasher _oldHasher = null!;
    private PasswordHasherSelector _hasherSelector = null!;
    private IdentityService _identityService = null!;
    private DurableSecurityMutationTestComposition _composition = null!;

    [SetUp]
    public void SetUp()
    {
        _repositoryMock = new Mock<IUserRepository>();
        _credentialRepositoryMock = new Mock<ICredentialRepository>();
        _secretProtectorMock = new Mock<ISecretProtector>();
        _timeProvider = new FakeTimeProvider();
        _composition = new DurableSecurityMutationTestComposition(participants: [_repositoryMock.Object, _credentialRepositoryMock.Object]);

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
            _credentialRepositoryMock.Object,
            _secretProtectorMock.Object,
            _composition.Transactions,
            new CredentialServiceDependencies(TimeProvider: _timeProvider, SecurityEventSink: _composition.Events));
        _identityService = CreateIdentityService(providers, credentialService);
        // Clear constructor-time Protect() calls so Verify() in tests only inspects invocations triggered by LoginAsync.
        _secretProtectorMock.Invocations.Clear();
    }

    [Test]
    public void ConstructorShouldThrowOnNullRepository()
    {
        var providerRegistry = new Mock<IAuthenticationProviderRegistry>();
        var authenticationPipeline = new Mock<IAuthenticationPipeline>();
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new IdentityService(null!, providerRegistry.Object, authenticationPipeline.Object));
    }

    [Test]
    public void ConstructorWithCollaboratorsShouldThrowOnNullProviderRegistry()
    {
        var authenticationPipeline = new Mock<IAuthenticationPipeline>();

        Assert.Throws<ArgumentNullException>(() => _ = new IdentityService(
            _repositoryMock.Object,
            // ReSharper disable once NullableWarningSuppressionIsUsed
            null!,
            authenticationPipeline.Object));
    }

    [Test]
    public void ConstructorWithCollaboratorsShouldThrowOnNullAuthenticationPipeline()
    {
        var providerRegistry = new Mock<IAuthenticationProviderRegistry>();

        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new IdentityService(
            _repositoryMock.Object,
            providerRegistry.Object,
            (IAuthenticationPipeline)null!));
    }

    [Test]
    public async Task LoginAsyncShouldDelegateToAuthenticationPipeline()
    {
        var providerRegistry = new Mock<IAuthenticationProviderRegistry>();
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
            authenticationPipeline.Object);

        var response = await service.LoginAsync(context, assertion, cancellationTokenSource.Token);

        Assert.That(response, Is.SameAs(expected));
        authenticationPipeline.Verify(p => p.LoginAsync(context, assertion, cancellationTokenSource.Token), Times.Once);
    }

    [Test]
    public void PublicIdentityServiceShouldNotExposeCredentialLinking()
    {
        Assert.That(typeof(IIdentityService).GetMethod("LinkCredentialAsync"), Is.Null);
    }

    [Test]
    public void PublicIdentityServiceShouldNotExposeGenericUserCreation()
    {
        Assert.That(typeof(IIdentityService).GetMethod("CreateUserAsync", [typeof(IUser), typeof(CancellationToken)]), Is.Null);
    }

    [Test]
    public async Task LoginAsyncWithValidLocalPasswordShouldReturnSuccess()
    {
        var email = "test@example.com";
        var password = "password123";
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, DisplayEmail = email };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Local, AuthenticationProviderKey.Local.Name, userId.ToString(), It.IsAny<CancellationToken>()))
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
        var user = new User { Id = userId, DisplayEmail = email };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Local, AuthenticationProviderKey.Local.Name, userId.ToString(), It.IsAny<CancellationToken>()))
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
        var user = new User { Id = userId, DisplayEmail = email };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Oidc, "Google", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var response = await _identityService.LoginAsync(new AuthenticationContext(email), assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.True);
            Assert.That(response.Claims, Is.EqualTo(assertion.Claims));
        }
    }

    [Test]
    public async Task LoginAsyncWithExternalProviderShouldNotRequireContextEmail()
    {
        var providerName = "Google";
        var providerKey = "google-sub-123";
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, DisplayEmail = "google-user@example.com" };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Oidc, providerName, providerKey, It.IsAny<CancellationToken>()))
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
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = email };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Oidc, providerName, providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        await _identityService.LoginAsync(new AuthenticationContext(email), assertion);

        _credentialRepositoryMock.Verify(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Oidc, providerName, providerKey, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task LinkCredentialAsyncWithExistingCredentialShouldFail()
    {
        var userId = Guid.NewGuid();
        var type = ProviderType.Oidc;
        var providerName = "Google";
        var providerKey = "sub";
        var user = new User { Id = userId, DisplayEmail = "test@example.com" };

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(type, providerName, providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var result = await LinkCredentialForTestAsync(userId, new ExternalIdentityAssertion(type, providerName, providerKey, new Dictionary<string, string>()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.AlreadyLinkedToSelf));
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
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "test@example.com" });
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, type, providerName, providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync((UserCredential?)null);

        await LinkCredentialForTestAsync(userId, assertion);

        _credentialRepositoryMock.Verify(r => r.CreateOrReplaceCredentialAsync(It.Is<UserCredential>(c =>
            c.UserId == userId &&
            c.ProviderType == type &&
            c.ProviderName == providerName &&
            c.ProviderKey == providerKey), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task LoginAsyncWithDisabledUserShouldReturnDisabledStatus()
    {
        var email = "inactive@example.com";
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = email, AccountState = UserAccountState.Disabled };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Local, AuthenticationProviderKey.Local.Name, user.Id.ToString(), It.IsAny<CancellationToken>()))
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
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = email };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Oidc, providerName, providerKey, It.IsAny<CancellationToken>()))
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
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = email };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Local, AuthenticationProviderKey.Local.Name, user.Id.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        _oldHasher.ShouldVerify = true;
        var expectedHash = Convert.ToBase64String(new byte[] { 0x02, 0, 0, 0 });

        var response = await _identityService.LoginAsync(new AuthenticationContext(email), new LocalPasswordAssertion("pass"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.True);
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.SuccessWithCredentialUpdate));
        }

        _credentialRepositoryMock.Verify(r => r.UpdateCredentialAsync(It.Is<UserCredential>(c =>
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
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "test@example.com" });
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Local, AuthenticationProviderKey.Local.Name, It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((UserCredential?)null);

        await LinkCredentialForTestAsync(userId, new LocalPasswordAssertion(password), password);

        _credentialRepositoryMock.Verify(r => r.CreateOrReplaceCredentialAsync(It.Is<UserCredential>(c =>
            c.UserId == userId &&
            c.CredentialValue == expectedHash), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public void LinkCredentialAsyncWithEmptyUserIdShouldThrowArgumentException()
    {
        Assert.ThrowsAsync<ArgumentException>(() =>
            LinkCredentialForTestAsync(Guid.Empty, new LocalPasswordAssertion("pass"), "pass"));
    }

    [Test]
    public async Task LinkCredentialAsyncWithAlreadyLinkedToAnotherUserShouldFail()
    {
        var userId = Guid.NewGuid();
        var anotherUserId = Guid.NewGuid();
        var type = ProviderType.Oidc;
        var providerName = "Google";
        var providerKey = "sub-123";
        var anotherUser = new User { Id = anotherUserId, DisplayEmail = "another@example.com" };
        var assertion = new ExternalIdentityAssertion(type, providerName, providerKey, new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "user@example.com" });
        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(type, providerName, providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(anotherUser);

        var result = await LinkCredentialForTestAsync(userId, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.AlreadyLinkedToOther));
        }
    }

    [Test]
    public async Task LinkCredentialAsyncWithConcurrentProviderKeyCollisionShouldFail()
    {
        var userId = Guid.NewGuid();
        var type = ProviderType.Oidc;
        var providerName = "Google";
        var providerKey = "sub-123";
        var assertion = new ExternalIdentityAssertion(type, providerName, providerKey, new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "user@example.com" });
        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(type, providerName, providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync((IUser?)null);
        _credentialRepositoryMock.Setup(r => r.CreateOrReplaceCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new CredentialProviderKeyConflictException());

        var result = await LinkCredentialForTestAsync(userId, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.AlreadyLinkedToOther));
        }
    }

    [Test]
    public async Task LinkCredentialAsyncWithLocalTypeShouldForceProviderNameToLocal()
    {
        var userId = Guid.NewGuid();
        var type = ProviderType.Local;
        var password = "password";

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "test@example.com" });
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, type, AuthenticationProviderKey.Local.Name, userId.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((UserCredential?)null);

        await LinkCredentialForTestAsync(userId, new LocalPasswordAssertion(password), password);

        _credentialRepositoryMock.Verify(r => r.CreateOrReplaceCredentialAsync(It.Is<UserCredential>(c =>
            c.ProviderName == AuthenticationProviderKey.Local.Name), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public void LinkCredentialAsyncWithLocalTypeAndMissingPasswordShouldThrowArgumentException()
    {
        var userId = Guid.NewGuid();

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "test@example.com" });

        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.CatchAsync<ArgumentException>(() => LinkCredentialForTestAsync(userId, new LocalPasswordAssertion(null!)));
    }

    [Test]
    public async Task LoginAsyncWithOAuthAssertionShouldReturnSuccess()
    {
        var email = "oauth-user@example.com";
        var providerKey = "oauth-sub-123";
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, DisplayEmail = email };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.OAuth, "GitHub", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var response = await _identityService.LoginAsync(new AuthenticationContext(email), assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.True);
            Assert.That(response.Claims, Is.EqualTo(assertion.Claims));
        }
    }

    [Test]
    public async Task LoginAsyncWithRehashUpdateExceptionShouldStillReturnSuccess()
    {
        var email = "rehash-fail@example.com";
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = email };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Local, AuthenticationProviderKey.Local.Name, user.Id.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);
        _credentialRepositoryMock.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
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
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = email };
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
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com" };
        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(provider.Type, provider.Name, providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var result = await _identityService.FindByProviderKeyAsync(provider, providerKey);

        Assert.That(result, Is.EqualTo(user));
    }

    [Test]
    public void FindByProviderKeyAsyncWithUninitializedProviderShouldThrow()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentException>(() => _identityService.FindByProviderKeyAsync(default, "key"));
            Assert.ThrowsAsync<ArgumentException>(() => _identityService.FindByProviderKeyAsync(new AuthenticationProviderKey((ProviderType)ProviderType.StorageFallbackValue, "unknown"), "key"));
        }
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

        var result = await LinkCredentialForTestAsync(userId, new LocalPasswordAssertion("pass"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
        }
    }

    [Test]
    public async Task LinkCredentialAsyncWithUnsupportedProviderShouldFail()
    {
        var userId = Guid.NewGuid();
        var assertionMock = new Mock<IAuthenticationAssertion>();
        assertionMock.Setup(a => a.ProviderIdentity).Returns(new AuthenticationProviderKey((ProviderType)"Unsupported", "Unsupported"));

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "test@example.com" });

        var result = await LinkCredentialForTestAsync(userId, assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ProviderUnsupported));
        }
    }

    [Test]
    public async Task LinkCredentialAsyncWithSameUserAlreadyLinkedShouldFail()
    {
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, DisplayEmail = "test@example.com" };
        var assertion = new LocalPasswordAssertion("pass");

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Local, AuthenticationProviderKey.Local.Name, userId.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var result = await LinkCredentialForTestAsync(userId, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.AlreadyLinkedToSelf));
        }
    }

    [Test]
    public async Task LinkCredentialAsyncWithSameUserAlreadyLinkedExternalShouldFail()
    {
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, DisplayEmail = "test@example.com" };
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "sub", new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var result = await LinkCredentialForTestAsync(userId, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.AlreadyLinkedToSelf));
        }
    }

    [Test]
    public async Task LoginAsyncWithRehashNeededButNullCredentialShouldNotAttemptUpdate()
    {
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com" };
        var providerMock = new Mock<IPrimaryAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey((ProviderType)"MOCK", "MOCK"));
        providerMock.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.SucceededWithCredentialUpdate, NewCredentialValue: "new-hash"));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<Guid>()))
            .Returns("key");
        providerMock.As<IAuthenticationUserResolver>().Setup(p => p.FindUserAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<AuthenticationContext>(), It.IsAny<IUserLookup>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var assertion = new ExternalIdentityAssertion((ProviderType)"MOCK", "MOCK", "key", new Dictionary<string, string>());

        var credentialService = CreateCredentialService();
        var service = CreateIdentityService([providerMock.Object], credentialService);
        // Clear constructor-time Protect() calls so Verify() in this test only inspects invocations triggered by LoginAsync.
        _secretProtectorMock.Invocations.Clear();

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, (ProviderType)"MOCK", "MOCK", "key", It.IsAny<CancellationToken>()))
            .ReturnsAsync((UserCredential?)null);

        var response = await service.LoginAsync(new AuthenticationContext("test@example.com"), assertion);

        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.SuccessWithCredentialUpdate));
        _credentialRepositoryMock.Verify(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task LoginAsyncWithRehashNeededButNoNewValueShouldNotAttemptUpdate()
    {
        var email = "rehash@example.com";
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = email };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Local, AuthenticationProviderKey.Local.Name, user.Id.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        _oldHasher.ShouldVerify = true;
        // Mocking rehash needed but returning null for new value
        var providerMock = new Mock<IPrimaryAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(AuthenticationProviderKey.Local);
        providerMock.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.SucceededWithCredentialUpdate, NewCredentialValue: null));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<Guid>())).Returns(user.Id.ToString());
        providerMock.As<IAuthenticationUserResolver>().Setup(p => p.FindUserAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<AuthenticationContext>(), It.IsAny<IUserLookup>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var credentialService = CreateCredentialService();
        var service = CreateIdentityService([providerMock.Object], credentialService);
        // Clear constructor-time Protect() calls so Verify() in this test only inspects invocations triggered by LoginAsync.
        _secretProtectorMock.Invocations.Clear();

        var response = await service.LoginAsync(new AuthenticationContext(email), new LocalPasswordAssertion("pass"));

        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.SuccessWithCredentialUpdate));
        _credentialRepositoryMock.Verify(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task LinkCredentialAsyncWithNullValueDoesNotEncryptCredential()
    {
        var userId = Guid.NewGuid();
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "sub", new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "test@example.com" });

        await LinkCredentialForTestAsync(userId, assertion);

        _credentialRepositoryMock.Verify(r => r.CreateOrReplaceCredentialAsync(It.Is<UserCredential>(c =>
            c.CredentialValue == null), It.IsAny<CancellationToken>()), Times.Once);

        _secretProtectorMock.Verify(s => s.Protect(It.IsAny<string>()), Times.Never);
    }

    [Test]
    public async Task LoginAsyncWithUnprotectFailureShouldReturnFailedEvenIfAuthenticateSucceeds()
    {
        var email = "test@example.com";
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = email };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(It.IsAny<Guid>(), It.IsAny<ProviderType>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
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
        var user = new User { Id = userId, DisplayEmail = "test@example.com" };

        var providerMock = new Mock<IPrimaryAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey((ProviderType)"MOCK", "MOCK"));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<Guid>()))
            .Returns(string.Empty);

        var assertion = new ExternalIdentityAssertion((ProviderType)"MOCK", "MOCK", "key", new Dictionary<string, string>());

        var credentialService = CreateCredentialService();
        var service = CreateIdentityService([providerMock.Object], credentialService);
        // Clear constructor-time Protect() calls so Verify() in this test only inspects invocations triggered by LoginAsync.
        _secretProtectorMock.Invocations.Clear();

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var result = await LinkCredentialForTestAsync(userId, assertion, providers: [providerMock.Object]);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidProviderKey));
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
        var providerMock = new Mock<IPrimaryAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey((ProviderType)"MOCK", "MOCK"));
        providerMock.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.SucceededWithCredentialUpdate));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<Guid>()))
            .Returns("key");

        var assertionMock = new Mock<IAuthenticationAssertion>();
        assertionMock.Setup(a => a.ProviderIdentity).Returns(new AuthenticationProviderKey((ProviderType)"MOCK", "MOCK"));

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((IUser?)null);

        var credentialService = CreateCredentialService();
        var service = CreateIdentityService([providerMock.Object], credentialService);
        // Clear constructor-time Protect() calls so Verify() in this test only inspects invocations triggered by LoginAsync.
        _secretProtectorMock.Invocations.Clear();

        var response = await service.LoginAsync(new AuthenticationContext("test@example.com"), assertionMock.Object);

        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
    }

    [Test]
    public async Task LinkCredentialAsyncWithExternalAssertionAlreadyLinkedToSameUserShouldFail()
    {
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, DisplayEmail = "test@example.com" };
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "sub", new Dictionary<string, string>());

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var result = await LinkCredentialForTestAsync(userId, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.AlreadyLinkedToSelf));
        }
    }

    [Test]
    public async Task LoginAsyncWithFoundCredentialButNullUserShouldReturnFailed()
    {
        var providerMock = new Mock<IPrimaryAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey((ProviderType)"MOCK", "MOCK"));
        providerMock.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<Guid>()))
            .Returns("key");

        var assertionMock = new Mock<IAuthenticationAssertion>();
        assertionMock.Setup(a => a.ProviderIdentity).Returns(new AuthenticationProviderKey((ProviderType)"MOCK", "MOCK"));

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((IUser?)null);

        var credentialService = CreateCredentialService();
        var service = CreateIdentityService([providerMock.Object], credentialService);
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
        var user = new User { Id = userId, DisplayEmail = "saml@example.com" };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Saml2, "Okta", providerKey, It.IsAny<CancellationToken>()))
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
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "test@example.com" });

        await LinkCredentialForTestAsync(userId, assertion, plainToken);

        _credentialRepositoryMock.Verify(r => r.CreateOrReplaceCredentialAsync(It.Is<UserCredential>(c =>
            c.CredentialValue == protectedToken), It.IsAny<CancellationToken>()), Times.Once);
        _secretProtectorMock.Verify(s => s.Protect(plainToken), Times.Once);
    }

    [Test]
    public async Task LoginAsyncWithExternalProviderShouldUnprotectCredentialValue()
    {
        var email = "test@example.com";
        var providerKey = "sub-123";
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, DisplayEmail = email };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Oidc, "Google", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        // Mock a provider to capture the credential passed to it
        var providerMock = new Mock<IPrimaryAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);

        string? capturedCredentialValue = null;
        providerMock.Setup(p => p.AuthenticateAsync(assertion, It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .Callback<IAuthenticationAssertion, UserCredential, CancellationToken>((_, c, _) => capturedCredentialValue = c.CredentialValue)
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded));

        providerMock.Setup(p => p.GetProviderKey(assertion, user.Id)).Returns(providerKey);
        providerMock.As<IAuthenticationUserResolver>().Setup(p => p.FindUserAsync(assertion, It.IsAny<AuthenticationContext>(), It.IsAny<IUserLookup>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var credentialService = CreateCredentialService();
        var service = CreateIdentityService([providerMock.Object], credentialService);
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
        var user = new User { Id = userId, DisplayEmail = email };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Local, AuthenticationProviderKey.Local.Name, userId.ToString(), It.IsAny<CancellationToken>()))
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
        var user = new User { Id = userId, DisplayEmail = email };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.OAuth, "GitHub", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        // Mock a provider that wants to update the token
        var providerMock = new Mock<IPrimaryAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.OAuth, "GitHub"));
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);
        providerMock.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.SucceededWithCredentialUpdate, NewCredentialValue: newTokenPlain));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<Guid>())).Returns(providerKey);
        providerMock.As<IAuthenticationUserResolver>().Setup(p => p.FindUserAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<AuthenticationContext>(), It.IsAny<IUserLookup>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var credentialService = CreateCredentialService();
        var service = CreateIdentityService([providerMock.Object], credentialService);
        // Clear constructor-time Protect() calls so Verify() in this test only inspects invocations triggered by LoginAsync.
        _secretProtectorMock.Invocations.Clear();
        await service.LoginAsync(new AuthenticationContext(email), assertion);

        _credentialRepositoryMock.Verify(r => r.UpdateCredentialAsync(It.Is<UserCredential>(c =>
            c.CredentialValue == newTokenProtected), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);
        _secretProtectorMock.Verify(s => s.Protect(newTokenPlain), Times.Once);
    }

    [Test]
    public async Task LoginAsyncWithExternalProviderAndCredentialWithNullValueAndDummyUnprotectFailureShouldReturnSuccess()
    {
        var email = "test@example.com";
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = email };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(It.IsAny<Guid>(), It.IsAny<ProviderType>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(It.IsAny<Guid>(), ProviderType.Oidc, "Google", providerKey, It.IsAny<CancellationToken>()))
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(It.IsAny<Guid>(), ProviderType.Oidc, "Google", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync((UserCredential?)null);

        await _identityService.LoginAsync(new AuthenticationContext(email), assertion);

        _secretProtectorMock.Verify(s => s.Unprotect(It.IsAny<string>()), Times.Once);
    }

    [Test]
    public async Task LoginAsyncWithExternalProviderAndMalformedCredentialShouldFailBeforeProviderAuthentication()
    {
        var email = "test@example.com";
        var providerKey = "sub-123";
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, DisplayEmail = email };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Oidc, "Google", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        _secretProtectorMock.Setup(s => s.Unprotect(malformedToken))
            .Throws(new System.Security.Cryptography.CryptographicException());

        var providerMock = new Mock<IPrimaryAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);
        providerMock.Setup(p => p.GetProviderKey(assertion, user.Id)).Returns(providerKey);
        providerMock.As<IAuthenticationUserResolver>().Setup(p => p.FindUserAsync(assertion, It.IsAny<AuthenticationContext>(), It.IsAny<IUserLookup>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var credentialService = CreateCredentialService();
        var service = CreateIdentityService([providerMock.Object], credentialService);
        // Clear constructor-time Protect() calls so Verify() in this test only inspects invocations triggered by LoginAsync.
        _secretProtectorMock.Invocations.Clear();

        var response = await service.LoginAsync(new AuthenticationContext(email), assertion);

        Assert.That(response.Succeeded, Is.False);
        providerMock.Verify(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential?>(), It.IsAny<CancellationToken>()), Times.Never);
        Assert.That(credential.CredentialValue, Is.EqualTo(malformedToken));
    }

    [Test]
    public async Task LoginAsyncWithExternalProviderAndNullCredentialValueShouldReturnSuccess()
    {
        var email = "test@example.com";
        var providerKey = "sub-123";
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, DisplayEmail = email };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Oidc, "Google", providerKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var providerMock = new Mock<IPrimaryAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);
        providerMock.Setup(p => p.AuthenticateAsync(assertion, It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded));
        providerMock.Setup(p => p.GetProviderKey(assertion, user.Id)).Returns(providerKey);
        providerMock.As<IAuthenticationUserResolver>().Setup(p => p.FindUserAsync(assertion, It.IsAny<AuthenticationContext>(), It.IsAny<IUserLookup>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var credentialService = CreateCredentialService();
        var service = CreateIdentityService([providerMock.Object], credentialService);
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

        _credentialRepositoryMock.Verify(r => r.GetCredentialForUserAsync(
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
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = email };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Local, AuthenticationProviderKey.Local.Name, user.Id.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);
        _credentialRepositoryMock.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("Database failure"));

        _oldHasher.ShouldVerify = true;

        var response = await _identityService.LoginAsync(new AuthenticationContext(email), new LocalPasswordAssertion("pass"));

        Assert.That(response.Succeeded, Is.True);
        _credentialRepositoryMock.Verify(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task LoginAsyncWithRehashUpdateConflictShouldStillReturnSuccessWithCredentialUpdate()
    {
        var email = "test@example.com";
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = email };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Local, AuthenticationProviderKey.Local.Name, user.Id.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);
        _credentialRepositoryMock.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), "v1", It.IsAny<CancellationToken>()))
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
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = email };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Local, AuthenticationProviderKey.Local.Name, user.Id.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);
        _credentialRepositoryMock.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), "v1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        var response = await _identityService.LoginAsync(new AuthenticationContext(email), new LocalPasswordAssertion("pass"));

        Assert.That(response.Succeeded, Is.True);
    }

    [Test]
    public async Task LoginAsyncShouldUpdateLastUsedAt()
    {
        var email = "test@example.com";
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = email };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Local, AuthenticationProviderKey.Local.Name, user.Id.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var startTime = _timeProvider.GetUtcNow();
        await _identityService.LoginAsync(new AuthenticationContext(email), new LocalPasswordAssertion("pass"));
        var endTime = _timeProvider.GetUtcNow();

        _credentialRepositoryMock.Verify(r => r.UpdateCredentialAsync(It.Is<UserCredential>(c =>
            c.LastUsedAt >= startTime && c.LastUsedAt <= endTime), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task LoginAsyncShouldPreserveAndUpdateMetadata()
    {
        var email = "test@example.com";
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = email };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var providerMock = new Mock<IPrimaryAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);
        providerMock.Setup(p => p.AuthenticateAsync(assertion, It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded, NewMetadata: "new-metadata"));
        providerMock.Setup(p => p.GetProviderKey(assertion, user.Id)).Returns("sub");
        providerMock.As<IAuthenticationUserResolver>().Setup(p => p.FindUserAsync(assertion, It.IsAny<AuthenticationContext>(), It.IsAny<IUserLookup>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var credentialService = CreateCredentialService();
        var service = CreateIdentityService([providerMock.Object], credentialService);
        // Clear constructor-time Protect() calls so Verify() in this test only inspects invocations triggered by LoginAsync.
        _secretProtectorMock.Invocations.Clear();
        await service.LoginAsync(new AuthenticationContext(email), assertion);

        _credentialRepositoryMock.Verify(r => r.UpdateCredentialAsync(It.Is<UserCredential>(c =>
            c.Metadata == "new-metadata" && c.CredentialValue == "protected(token)"), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task LoginAsyncShouldConsumeCredentialAtomicallyIfRequested()
    {
        var email = "test@example.com";
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = email };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var providerMock = new Mock<IPrimaryAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);
        providerMock.Setup(p => p.AuthenticateAsync(assertion, It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded, IsCredentialConsumed: true));
        providerMock.Setup(p => p.GetProviderKey(assertion, user.Id)).Returns("sub");
        providerMock.As<IAuthenticationUserResolver>().Setup(p => p.FindUserAsync(assertion, It.IsAny<AuthenticationContext>(), It.IsAny<IUserLookup>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _credentialRepositoryMock.Setup(r => r.ConsumeCredentialAsync(credential.Id, "v1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var credentialService = CreateCredentialService();
        var service = CreateIdentityService([providerMock.Object], credentialService);
        // Clear constructor-time Protect() calls so Verify() in this test only inspects invocations triggered by LoginAsync.
        _secretProtectorMock.Invocations.Clear();
        var response = await service.LoginAsync(new AuthenticationContext(email), assertion);

        Assert.That(response.Succeeded, Is.True);
        _credentialRepositoryMock.Verify(r => r.ConsumeCredentialAsync(credential.Id, "v1", It.IsAny<CancellationToken>()), Times.Once);
        _credentialRepositoryMock.Verify(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task LoginAsyncShouldPreserveExistingMetadataWhenOnlyLastUsedAtUpdates()
    {
        var email = "test@example.com";
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = email };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Local, AuthenticationProviderKey.Local.Name, user.Id.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        await _identityService.LoginAsync(new AuthenticationContext(email), new LocalPasswordAssertion("pass"));

        _credentialRepositoryMock.Verify(r => r.UpdateCredentialAsync(It.Is<UserCredential>(c =>
            c.Metadata == "important-data" && c.LastUsedAt != null), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task LoginAsyncShouldUpdateMetadataWhenCredentialValueIsNull()
    {
        var email = "test@example.com";
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = email };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var providerMock = new Mock<IPrimaryAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);
        providerMock.Setup(p => p.AuthenticateAsync(assertion, It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded, NewMetadata: "new-metadata"));
        providerMock.Setup(p => p.GetProviderKey(assertion, user.Id)).Returns("sub");
        providerMock.As<IAuthenticationUserResolver>().Setup(p => p.FindUserAsync(assertion, It.IsAny<AuthenticationContext>(), It.IsAny<IUserLookup>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var credentialService = CreateCredentialService();
        var service = CreateIdentityService([providerMock.Object], credentialService);
        // Clear constructor-time Protect() calls so Verify() in this test only inspects invocations triggered by LoginAsync.
        _secretProtectorMock.Invocations.Clear();
        await service.LoginAsync(new AuthenticationContext(email), assertion);

        _credentialRepositoryMock.Verify(r => r.UpdateCredentialAsync(It.Is<UserCredential>(c =>
            c.Metadata == "new-metadata" && c.CredentialValue == null), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task LoginAsyncShouldReturnFailedWhenAtomicConsumeReturnsFalse()
    {
        var email = "test@example.com";
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = email };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var providerMock = new Mock<IPrimaryAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);
        providerMock.Setup(p => p.AuthenticateAsync(assertion, It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded, IsCredentialConsumed: true));
        providerMock.Setup(p => p.GetProviderKey(assertion, user.Id)).Returns("sub");
        providerMock.As<IAuthenticationUserResolver>().Setup(p => p.FindUserAsync(assertion, It.IsAny<AuthenticationContext>(), It.IsAny<IUserLookup>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _credentialRepositoryMock.Setup(r => r.ConsumeCredentialAsync(credential.Id, "v1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        var credentialService = CreateCredentialService();
        var service = CreateIdentityService([providerMock.Object], credentialService);
        // Clear constructor-time Protect() calls so Verify() in this test only inspects invocations triggered by LoginAsync.
        _secretProtectorMock.Invocations.Clear();

        var response = await service.LoginAsync(new AuthenticationContext(email), assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
        }
        _credentialRepositoryMock.Verify(r => r.ConsumeCredentialAsync(credential.Id, "v1", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public Task LoginAsyncShouldThrowIfCredentialConsumptionIsCancelled()
    {
        var email = "test@example.com";
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = email };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var providerMock = new Mock<IPrimaryAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);
        providerMock.Setup(p => p.AuthenticateAsync(assertion, It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded, IsCredentialConsumed: true));
        providerMock.Setup(p => p.GetProviderKey(assertion, user.Id)).Returns("sub");
        providerMock.As<IAuthenticationUserResolver>().Setup(p => p.FindUserAsync(assertion, It.IsAny<AuthenticationContext>(), It.IsAny<IUserLookup>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _credentialRepositoryMock.Setup(r => r.ConsumeCredentialAsync(credential.Id, "v1", It.IsAny<CancellationToken>()))
            .ThrowsAsync(new OperationCanceledException());

        var credentialService = CreateCredentialService();
        var service = CreateIdentityService([providerMock.Object], credentialService);
        // Clear constructor-time Protect() calls so Verify() in this test only inspects invocations triggered by LoginAsync.
        _secretProtectorMock.Invocations.Clear();

        Assert.ThrowsAsync<OperationCanceledException>(async () => await service.LoginAsync(new AuthenticationContext(email), assertion));
        return Task.CompletedTask;
    }

    [Test]
    public async Task LoginAsyncShouldNotReProtectWhenOnlyMetadataChanges()
    {
        var email = "test@example.com";
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = email };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var providerMock = new Mock<IPrimaryAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);

        // Metadata updated, but no new credential value
        providerMock.Setup(p => p.AuthenticateAsync(assertion, It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded, NewMetadata: "new-meta"));
        providerMock.Setup(p => p.GetProviderKey(assertion, user.Id)).Returns("sub");
        providerMock.As<IAuthenticationUserResolver>().Setup(p => p.FindUserAsync(assertion, It.IsAny<AuthenticationContext>(), It.IsAny<IUserLookup>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var credentialService = CreateCredentialService();
        var service = CreateIdentityService([providerMock.Object], credentialService);
        // Clear constructor-time Protect() calls so Verify() in this test only inspects invocations triggered by LoginAsync.
        _secretProtectorMock.Invocations.Clear();
        await service.LoginAsync(new AuthenticationContext(email), assertion);

        _credentialRepositoryMock.Verify(r => r.UpdateCredentialAsync(It.Is<UserCredential>(c =>
            c.CredentialValue == "protected(existing)" && c.Metadata == "new-meta"), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);

        _secretProtectorMock.Verify(s => s.Protect(It.IsAny<string>()), Times.Never);
    }

    [Test]
    public async Task LoginAsyncShouldPreserveOldCredentialValueWhenNewValueIsNullAndUpdateRequested()
    {
        var email = "test@example.com";
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = email };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var providerMock = new Mock<IPrimaryAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);

        // Return a credential update status, but NewCredentialValue = null
        providerMock.Setup(p => p.AuthenticateAsync(assertion, It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.SucceededWithCredentialUpdate, NewCredentialValue: null));
        providerMock.Setup(p => p.GetProviderKey(assertion, user.Id)).Returns("sub");
        providerMock.As<IAuthenticationUserResolver>().Setup(p => p.FindUserAsync(assertion, It.IsAny<AuthenticationContext>(), It.IsAny<IUserLookup>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var credentialService = CreateCredentialService();
        var service = CreateIdentityService([providerMock.Object], credentialService);
        // Clear constructor-time Protect() calls so Verify() in this test only inspects invocations triggered by LoginAsync.
        _secretProtectorMock.Invocations.Clear();
        await service.LoginAsync(new AuthenticationContext(email), assertion);

        // Verify that we updated the credential, but with the OLD value (preserved)
        _credentialRepositoryMock.Verify(r => r.UpdateCredentialAsync(It.Is<UserCredential>(c =>
            c.CredentialValue == "protected(old-value)"), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);

        // Ensure Protect was not called for this update (excluding dummy init)
        _secretProtectorMock.Verify(s => s.Protect(It.IsAny<string>()), Times.Never);
    }

    [Test]
    public async Task LoginAsyncShouldUpdateMetadataWhenExplicitlyEmptyAndCurrentIsNull()
    {
        var email = "test@example.com";
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = email };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var providerMock = new Mock<IPrimaryAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);
        providerMock.Setup(p => p.AuthenticateAsync(assertion, It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded, NewMetadata: string.Empty)); // Explicitly empty
        providerMock.Setup(p => p.GetProviderKey(assertion, user.Id)).Returns("sub");
        providerMock.As<IAuthenticationUserResolver>().Setup(p => p.FindUserAsync(assertion, It.IsAny<AuthenticationContext>(), It.IsAny<IUserLookup>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var credentialService = CreateCredentialService();
        var service = CreateIdentityService([providerMock.Object], credentialService);
        _secretProtectorMock.Invocations.Clear();
        await service.LoginAsync(new AuthenticationContext(email), assertion);

        // Verify update occurred because "" != null
        _credentialRepositoryMock.Verify(r => r.UpdateCredentialAsync(It.Is<UserCredential>(c =>
            c.Metadata == string.Empty), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task LoginAsyncShouldNotUpdateMetadataWhenProviderReturnsNull()
    {
        var email = "test@example.com";
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = email };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var providerMock = new Mock<IPrimaryAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);
        providerMock.Setup(p => p.AuthenticateAsync(assertion, It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded, NewMetadata: null)); // No change
        providerMock.Setup(p => p.GetProviderKey(assertion, user.Id)).Returns("sub");
        providerMock.As<IAuthenticationUserResolver>().Setup(p => p.FindUserAsync(assertion, It.IsAny<AuthenticationContext>(), It.IsAny<IUserLookup>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var credentialService = CreateCredentialService();
        var service = CreateIdentityService([providerMock.Object], credentialService);
        _secretProtectorMock.Invocations.Clear();
        await service.LoginAsync(new AuthenticationContext(email), assertion);

        // Verify NO update occurred because NewMetadata is null
        _credentialRepositoryMock.Verify(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task LoginAsyncShouldNotUpdateCredentialIfLastUsedAtIsRecent()
    {
        var email = "test@example.com";
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = email };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Local, AuthenticationProviderKey.Local.Name, user.Id.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        await _identityService.LoginAsync(new AuthenticationContext(email), new LocalPasswordAssertion("pass"));

        // Verify UpdateCredentialAsync was NEVER called because 30 seconds < 1 minute threshold
        _credentialRepositoryMock.Verify(r => r.UpdateCredentialAsync(It.Is<UserCredential>(c => c.Id == credential.Id), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task LoginAsyncShouldGenerateRandomProviderKeyIfProviderReturnsNullOrEmpty()
    {
        var email = "test@example.com";
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = email };

        var providerMock = new Mock<IPrimaryAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey((ProviderType)"MOCK", "MOCK"));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<Guid>())).Returns(string.Empty); // Return empty
        providerMock.As<IAuthenticationUserResolver>().Setup(p => p.FindUserAsync(It.IsAny<IAuthenticationAssertion>(), It.Is<AuthenticationContext>(c => c.Email == email), It.IsAny<IUserLookup>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        providerMock.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded));

        var assertion = new ExternalIdentityAssertion((ProviderType)"MOCK", "MOCK", "key", new Dictionary<string, string>());

        var credentialService = CreateCredentialService();
        var service = CreateIdentityService([providerMock.Object], credentialService);
        // Clear constructor-time Protect() calls so Verify() in this test only inspects invocations triggered by LoginAsync.
        _secretProtectorMock.Invocations.Clear();

        await service.LoginAsync(new AuthenticationContext(email), assertion);

        // Verify that GetCredentialForUserAsync was called with a generated key (not the empty one returned by provider)
        _credentialRepositoryMock.Verify(r => r.GetCredentialForUserAsync(
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
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = email };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Local, AuthenticationProviderKey.Local.Name, user.Id.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var providerMock = new Mock<IPrimaryAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(AuthenticationProviderKey.Local);
        providerMock.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.SucceededWithCredentialUpdate, NewCredentialValue: "new-hash"));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<Guid>())).Returns(user.Id.ToString());
        providerMock.As<IAuthenticationUserResolver>().Setup(p => p.FindUserAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<AuthenticationContext>(), It.IsAny<IUserLookup>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var credentialService = CreateCredentialService();
        var service = CreateIdentityService([providerMock.Object], credentialService);
        _secretProtectorMock.Invocations.Clear();

        var response = await service.LoginAsync(new AuthenticationContext(email), new LocalPasswordAssertion("pass"));

        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.SuccessWithCredentialUpdate));
        _credentialRepositoryMock.Verify(r => r.UpdateCredentialAsync(It.Is<UserCredential>(c => c.CredentialValue == "new-hash"), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task LoginAsyncWithRequiredUpdateFailureShouldReturnFailed()
    {
        var email = "test@example.com";
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = email };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Local, "LOCAL", It.IsAny<string>(), It.IsAny<CancellationToken>())).ReturnsAsync(credential);

        var providerMock = new Mock<IPrimaryAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Local, "LOCAL"));
        providerMock.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded, CredentialUpdateRequirement: CredentialUpdateRequirement.Required, NewCredentialValue: "new"));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<Guid>())).Returns(user.Id.ToString());
        providerMock.As<IAuthenticationUserResolver>().Setup(p => p.FindUserAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<AuthenticationContext>(), It.IsAny<IUserLookup>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _credentialRepositoryMock.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("Update failed"));

        var credentialService = CreateCredentialService();
        var service = CreateIdentityService([providerMock.Object], credentialService);

        var response = await service.LoginAsync(new AuthenticationContext(email), new LocalPasswordAssertion("pass"));

        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
    }

    [Test]
    public async Task LoginAsyncWithConsumptionFailureShouldReturnFailed()
    {
        var email = "test@example.com";
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = email };
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
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Oidc, "Google", "key", It.IsAny<CancellationToken>())).ReturnsAsync(credential);

        var providerMock = new Mock<IPrimaryAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded, IsCredentialConsumed: true));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<Guid>())).Returns("key");
        providerMock.As<IAuthenticationUserResolver>().Setup(p => p.FindUserAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<AuthenticationContext>(), It.IsAny<IUserLookup>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _credentialRepositoryMock.Setup(r => r.ConsumeCredentialAsync(credential.Id, "v1", It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("Consume failed"));

        var credentialService = CreateCredentialService();
        var service = CreateIdentityService([providerMock.Object], credentialService);

        var response = await service.LoginAsync(new AuthenticationContext(email), new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "key", new Dictionary<string, string>()));

        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
    }

    private CredentialService CreateCredentialService() => new(
        _repositoryMock.Object,
        _credentialRepositoryMock.Object,
        _secretProtectorMock.Object,
        _composition.Transactions,
        new CredentialServiceDependencies(TimeProvider: _timeProvider, SecurityEventSink: _composition.Events));

    private IdentityService CreateIdentityService(
        IEnumerable<IAuthenticationProvider> providers,
        ICredentialService credentialService,
        IAshlarTransactionProvider? transactionProvider = null,
        ISecurityEventSink? securityEventSink = null)
    {
        transactionProvider ??= AshlarDurableTransactionProvider.Create(new NullTransactionProvider());
        var providerRegistry = new AuthenticationProviderRegistry(providers);
        var pipeline = new AuthenticationPipeline(
            providerRegistry,
            credentialService,
            AshlarDurableTransactionProvider.Create(transactionProvider),
            AllowPrimaryAuthenticationRateLimiter.Instance,
            AllowAuthenticationFactorRateLimiter.Instance,
            new AuthenticationPipelineDependencies(securityEventSink, _timeProvider));

        return new IdentityService(
            _repositoryMock.Object,
            providerRegistry,
            pipeline);
    }

    private Task<Result> LinkCredentialForTestAsync(
        Guid userId,
        IAuthenticationAssertion assertion,
        string? credentialValue = null,
        IEnumerable<IAuthenticationProvider>? providers = null)
    {
        providers ??=
        [
            new LocalPasswordProvider(_hasherSelector),
            new OidcAuthenticationProvider("Google"),
            new OidcAuthenticationProvider("GitHub"),
            new OAuthAuthenticationProvider("GitHub"),
            new Saml2AuthenticationProvider("Okta")
        ];

        var registry = new AuthenticationProviderRegistry(providers);
        if (!registry.TryGetProvider(assertion, out var provider))
        {
            return Task.FromResult(Result.Failure(AshlarFailureCodes.ProviderUnsupported, $"Provider '{assertion.ProviderIdentity}' is not supported."));
        }

        var credentialService = new CredentialService(
            _repositoryMock.Object,
            _credentialRepositoryMock.Object,
            _secretProtectorMock.Object,
            _composition.Transactions,
            new CredentialServiceDependencies(TimeProvider: _timeProvider, SecurityEventSink: _composition.Events));

        return credentialService.LinkCredentialAsync(new CredentialLinkRequest(userId, assertion, provider, credentialValue, null, new AuditContext(userId)));
    }
}
