using Ashlar.Identity.Providers.External;
using Ashlar.Security.Encryption;
using Ashlar.Testing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Tests.Identity.Features.Credentials;

internal sealed class CredentialServiceTests
{
    private Mock<IUserRepository> _repositoryMock = null!;
    private Mock<ICredentialRepository> _credentialRepositoryMock = null!;
    private Mock<ISecretProtector> _secretProtectorMock = null!;
    private FakeTimeProvider _timeProvider = null!;
    private CredentialService _service = null!;

    [SetUp]
    public void SetUp()
    {
        _repositoryMock = new Mock<IUserRepository>();
        _credentialRepositoryMock = new Mock<ICredentialRepository>();
        _secretProtectorMock = new Mock<ISecretProtector>();
        _timeProvider = new FakeTimeProvider();

        _secretProtectorMock.Setup(s => s.Protect(It.IsAny<string>())).Returns<string>(s => $"protected({s})");
        _secretProtectorMock.Setup(s => s.Unprotect(It.IsAny<string>())).Returns<string>(s => s.StartsWith("protected(", StringComparison.Ordinal) ? s[10..^1] : s);

        _service = new CredentialService(
            _repositoryMock.Object,
            _credentialRepositoryMock.Object,
            _secretProtectorMock.Object,
            new NullTransactionProvider(),
            new CredentialServiceDependencies(TimeProvider: _timeProvider));
    }

    [Test]
    public async Task UpdateCredentialUsageAsyncShouldUseClockForLastUsedAt()
    {
        var testTime = new DateTimeOffset(2025, 1, 1, 12, 0, 0, TimeSpan.Zero);
        _timeProvider.SetUtcNow(testTime);

        var credential = CreateCredential(Guid.NewGuid());
        credential.LastUsedAt = testTime.AddMinutes(-2);
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded);
        var providerMock = new Mock<IAuthenticationProvider>();

        _credentialRepositoryMock.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        await _service.UpdateCredentialUsageAsync(credential, null, result, providerMock.Object);

        Assert.That(credential.LastUsedAt, Is.EqualTo(testTime));
    }

    [Test]
    public async Task UpdateCredentialUsageAsyncShouldUseClockForUpdatedAt()
    {
        var testTime = new DateTimeOffset(2025, 1, 1, 12, 0, 0, TimeSpan.Zero);
        _timeProvider.SetUtcNow(testTime);

        var credential = CreateCredential(Guid.NewGuid());
        credential.Metadata = "old";
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded, NewMetadata: "new");
        var providerMock = new Mock<IAuthenticationProvider>();

        _credentialRepositoryMock.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        await _service.UpdateCredentialUsageAsync(credential, null, result, providerMock.Object);

        Assert.That(credential.UpdatedAt, Is.EqualTo(testTime));
    }

    [Test]
    public async Task LinkCredentialAsyncShouldUseClockForCreatedAt()
    {
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, DisplayEmail = "test@example.com" };
        var assertionMock = new Mock<IAuthenticationAssertion>();
        assertionMock.Setup(a => a.ProviderIdentity).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));

        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.GetProviderKey(assertionMock.Object, userId)).Returns("new-key");

        var testTime = new DateTimeOffset(2025, 1, 1, 12, 0, 0, TimeSpan.Zero);
        _timeProvider.SetUtcNow(testTime);

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, "Google", "new-key", It.IsAny<CancellationToken>())).ReturnsAsync((IUser?)null);

        await _service.LinkCredentialAsync(userId, assertionMock.Object, providerMock.Object);

        _credentialRepositoryMock.Verify(r => r.CreateOrReplaceCredentialAsync(It.Is<UserCredential>(c =>
            c.CreatedAt == testTime), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task ResolveAsyncShouldUseClockForExpiryCheck()
    {
        var testTime = new DateTimeOffset(2025, 1, 1, 12, 0, 0, TimeSpan.Zero);
        _timeProvider.SetUtcNow(testTime);

        var credential = CreateCredential(
            Guid.NewGuid(),
            expiresAt: testTime.AddSeconds(1)); // Not yet expired

        _repositoryMock.Setup(r => r.GetUserByIdAsync(credential.UserId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = credential.UserId, DisplayEmail = "test@example.com" });
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(credential.UserId, ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var resolvedCredential = await ResolveCredentialAsync(credential);
        Assert.That(resolvedCredential, Is.Not.Null, "Should be available at testTime");

        _timeProvider.Advance(TimeSpan.FromSeconds(2)); // Now it is expired

        var resolvedCredentialExpired = await ResolveCredentialAsync(credential);
        Assert.That(resolvedCredentialExpired, Is.Null, "Should be expired after advancing clock");
    }

    [Test]
    public async Task ResolveAsyncShouldReturnUnprotectedCredential()
    {
        var email = "test@example.com";
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, DisplayEmail = email };
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.Oidc,
            ProviderName = "Google",
            ProviderKey = "sub",
            Version = "v1",
            CreatedAt = _timeProvider.GetUtcNow(),
            Status = CredentialStatus.Active,
            CredentialValue = "protected(token)"
        };

        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<Guid>())).Returns("sub");
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);
        providerMock.Setup(p => p.FindUserAsync(It.IsAny<IAuthenticationAssertion>(), It.Is<AuthenticationContext>(c => c.Email == email), _repositoryMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var (resolvedUser, resolvedCredential, originalCredential, unprotectFailed) = await _service.ResolveAsync(new AuthenticationContext(email), new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "sub", new Dictionary<string, string>()), providerMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(resolvedUser, Is.EqualTo(user));
            Assert.That(resolvedCredential?.CredentialValue, Is.EqualTo("token"));
            Assert.That(originalCredential?.CredentialValue, Is.EqualTo("protected(token)"));
            Assert.That(unprotectFailed, Is.False);
        }
    }

    [Test]
    public async Task ResolveAsyncWithMissingUserShouldStillCallUnprotectForTiming()
    {
        var email = "ghost@example.com";
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<Guid>())).Returns("sub");
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);
        providerMock.Setup(p => p.FindUserAsync(It.IsAny<IAuthenticationAssertion>(), It.Is<AuthenticationContext>(c => c.Email == email), _repositoryMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync((IUser?)null);

        await _service.ResolveAsync(new AuthenticationContext(email), new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "sub", new Dictionary<string, string>()), providerMock.Object);

        _secretProtectorMock.Verify(s => s.Unprotect(It.IsAny<string>()), Times.Once);
    }

    [Test]
    public async Task ResolveAsyncShouldRespectUserIdFromContextWhenProviderFindUserReturnsNull()
    {
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, DisplayEmail = "test@example.com" };
        var context = new AuthenticationContext(UserId: userId);
        var assertionMock = new Mock<IAuthenticationAssertion>();
        var providerMock = new Mock<IAuthenticationProvider>();

        providerMock.Setup(p => p.FindUserAsync(assertionMock.Object, context, _repositoryMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync((IUser?)null);
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Mfa, "totp"));
        providerMock.Setup(p => p.GetProviderKey(assertionMock.Object, userId)).Returns(userId.ToString("D"));

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Mfa, "totp", userId.ToString("D"), It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateCredential(userId));

        var (resolvedUser, _, _, _) = await _service.ResolveAsync(context, assertionMock.Object, providerMock.Object);

        Assert.That(resolvedUser, Is.Not.Null);
        Assert.That(resolvedUser.Id, Is.EqualTo(userId));
        _repositoryMock.Verify(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task ResolveAsyncShouldRejectProviderUserFromDifferentTenant()
    {
        var contextTenantId = Guid.NewGuid();
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com", TenantId = Guid.NewGuid() };
        var context = new AuthenticationContext(TenantId: contextTenantId);
        var assertionMock = new Mock<IAuthenticationAssertion>();
        var providerMock = CreateProviderMock();
        providerMock.Setup(p => p.FindUserAsync(assertionMock.Object, context, _repositoryMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var (resolvedUser, resolvedCredential, _, _) = await _service.ResolveAsync(context, assertionMock.Object, providerMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(resolvedUser, Is.Null);
            Assert.That(resolvedCredential, Is.Null);
        }
        _credentialRepositoryMock.Verify(r => r.GetCredentialForUserAsync(user.Id, It.IsAny<ProviderType>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task ResolveAsyncShouldRejectTenantAwareGlobalUserWhenContextTenantIsSet()
    {
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com", TenantId = null };
        var context = new AuthenticationContext(TenantId: Guid.NewGuid());
        var assertionMock = new Mock<IAuthenticationAssertion>();
        var providerMock = CreateProviderMock();
        providerMock.Setup(p => p.FindUserAsync(assertionMock.Object, context, _repositoryMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var (resolvedUser, resolvedCredential, _, _) = await _service.ResolveAsync(context, assertionMock.Object, providerMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(resolvedUser, Is.Null);
            Assert.That(resolvedCredential, Is.Null);
        }
    }

    [Test]
    public async Task ResolveAsyncShouldRejectNonTenantUserWhenContextTenantIsSet()
    {
        var user = new NonTenantUser { Id = Guid.NewGuid(), DisplayEmail = "test@example.com" };
        var context = new AuthenticationContext(TenantId: Guid.NewGuid());
        var assertionMock = new Mock<IAuthenticationAssertion>();
        var providerMock = CreateProviderMock();
        providerMock.Setup(p => p.FindUserAsync(assertionMock.Object, context, _repositoryMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var (resolvedUser, resolvedCredential, _, _) = await _service.ResolveAsync(context, assertionMock.Object, providerMock.Object);

        Assert.That(resolvedUser, Is.Null);
    }

    [Test]
    public async Task ResolveAsyncShouldAcceptProviderUserFromMatchingTenant()
    {
        var tenantId = Guid.NewGuid();
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com", TenantId = tenantId };
        var credential = CreateCredential(user.Id);
        var context = new AuthenticationContext(TenantId: tenantId);
        var assertionMock = new Mock<IAuthenticationAssertion>();
        var providerMock = CreateProviderMock();
        providerMock.Setup(p => p.FindUserAsync(assertionMock.Object, context, _repositoryMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var (resolvedUser, resolvedCredential, _, _) = await _service.ResolveAsync(context, assertionMock.Object, providerMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(resolvedUser, Is.EqualTo(user));
            Assert.That(resolvedCredential, Is.Not.Null);
        }
    }

    [Test]
    public async Task ResolveAsyncShouldAcceptAnyUserWhenContextTenantIsNull()
    {
        var user = new NonTenantUser { Id = Guid.NewGuid(), DisplayEmail = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var context = new AuthenticationContext();
        var assertionMock = new Mock<IAuthenticationAssertion>();
        var providerMock = CreateProviderMock();
        providerMock.Setup(p => p.FindUserAsync(assertionMock.Object, context, _repositoryMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var (resolvedUser, resolvedCredential, _, _) = await _service.ResolveAsync(context, assertionMock.Object, providerMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(resolvedUser, Is.EqualTo(user));
            Assert.That(resolvedCredential, Is.Not.Null);
        }
    }

    [Test]
    public async Task ResolveAsyncShouldRejectContextUserIdFallbackFromDifferentTenant()
    {
        var userId = Guid.NewGuid();
        var context = new AuthenticationContext(TenantId: Guid.NewGuid(), UserId: userId);
        var user = new User { Id = userId, DisplayEmail = "test@example.com", TenantId = Guid.NewGuid() };
        var assertionMock = new Mock<IAuthenticationAssertion>();
        var providerMock = CreateProviderMock();
        providerMock.Setup(p => p.FindUserAsync(assertionMock.Object, context, _repositoryMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync((IUser?)null);
        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>())).ReturnsAsync(user);

        var (resolvedUser, resolvedCredential, _, _) = await _service.ResolveAsync(context, assertionMock.Object, providerMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(resolvedUser, Is.Null);
            Assert.That(resolvedCredential, Is.Null);
        }
        _credentialRepositoryMock.Verify(r => r.GetCredentialForUserAsync(userId, It.IsAny<ProviderType>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task UnprotectCredentialWithNoProtectionShouldReturnCredential()
    {
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Local,
            ProviderName = AuthenticationProviderKey.Local.Name,
            ProviderKey = "key",
            Version = "v1",
            CreatedAt = _timeProvider.GetUtcNow(),
            Status = CredentialStatus.Active,
            CredentialValue = "value"
        };
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(AuthenticationProviderKey.Local);
        providerMock.Setup(p => p.ProtectsCredentials).Returns(false);

        _repositoryMock.Setup(r => r.GetUserByIdAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = credential.UserId, DisplayEmail = "test@example.com" });
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(It.IsAny<Guid>(), It.IsAny<ProviderType>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var (_, resolvedCredential, _, _) = await _service.ResolveAsync(credential.UserId, new Mock<IAuthenticationAssertion>().Object, providerMock.Object);

        Assert.That(resolvedCredential?.CredentialValue, Is.EqualTo("value"));
    }

    [Test]
    public async Task ResolveAsyncWithUnavailableUnprotectedCredentialShouldReturnNullCredential()
    {
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Local,
            ProviderName = AuthenticationProviderKey.Local.Name,
            ProviderKey = "key",
            Version = "v1",
            CreatedAt = _timeProvider.GetUtcNow(),
            Status = CredentialStatus.Revoked,
            CredentialValue = "value"
        };
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(AuthenticationProviderKey.Local);
        providerMock.Setup(p => p.ProtectsCredentials).Returns(false);

        _repositoryMock.Setup(r => r.GetUserByIdAsync(credential.UserId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = credential.UserId, DisplayEmail = "test@example.com" });
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(credential.UserId, ProviderType.Local, AuthenticationProviderKey.Local.Name, "key", It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), credential.UserId)).Returns("key");

        var (_, resolvedCredential, originalCredential, unprotectFailed) = await _service.ResolveAsync(credential.UserId, new Mock<IAuthenticationAssertion>().Object, providerMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(resolvedCredential, Is.Null);
            Assert.That(originalCredential, Is.EqualTo(credential));
            Assert.That(unprotectFailed, Is.False);
        }
    }

    [Test]
    public async Task UpdateCredentialUsageAsyncWithMetadataChangeShouldUpdate()
    {
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Oidc,
            ProviderName = "Google",
            ProviderKey = "sub",
            Version = "v1",
            CreatedAt = _timeProvider.GetUtcNow(),
            Status = CredentialStatus.Active,
            Metadata = "old",
            LastUsedAt = _timeProvider.GetUtcNow()
        };
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded, NewMetadata: "new");
        var providerMock = new Mock<IAuthenticationProvider>();

        _credentialRepositoryMock.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        await _service.UpdateCredentialUsageAsync(credential, null, result, providerMock.Object);

        _credentialRepositoryMock.Verify(r => r.UpdateCredentialAsync(It.Is<UserCredential>(c => c.Metadata == "new"), "v1", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task UpdateCredentialUsageAsyncWithConsumedCredentialShouldConsumeAtomically()
    {
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Oidc,
            ProviderName = "Google",
            ProviderKey = "sub",
            Version = "v1",
            CreatedAt = _timeProvider.GetUtcNow(),
            Status = CredentialStatus.Active
        };
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded, IsCredentialConsumed: true);
        var providerMock = new Mock<IAuthenticationProvider>();

        _credentialRepositoryMock.Setup(r => r.ConsumeCredentialAsync(credential.Id, "v1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var consumed = await _service.UpdateCredentialUsageAsync(credential, null, result, providerMock.Object);

        Assert.That(consumed, Is.True);
        _credentialRepositoryMock.Verify(r => r.ConsumeCredentialAsync(credential.Id, "v1", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task UpdateCredentialUsageAsyncWithConsumedCredentialShouldReturnFalseWhenAtomicConsumeFails()
    {
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Oidc,
            ProviderName = "Google",
            ProviderKey = "sub",
            Version = "v1",
            CreatedAt = _timeProvider.GetUtcNow(),
            Status = CredentialStatus.Active
        };
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded, IsCredentialConsumed: true);
        var providerMock = new Mock<IAuthenticationProvider>();

        _credentialRepositoryMock.Setup(r => r.ConsumeCredentialAsync(credential.Id, "v1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        var consumed = await _service.UpdateCredentialUsageAsync(credential, null, result, providerMock.Object);

        Assert.That(consumed, Is.False);
    }

    [Test]
    public async Task UpdateCredentialUsageAsyncWithBestEffortUpdateConflictShouldReturnTrue()
    {
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Oidc,
            ProviderName = "Google",
            ProviderKey = "sub",
            Version = "v1",
            CreatedAt = _timeProvider.GetUtcNow(),
            Status = CredentialStatus.Active,
            LastUsedAt = _timeProvider.GetUtcNow().AddDays(-1)
        };
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded, CredentialUpdateRequirement: CredentialUpdateRequirement.BestEffort);
        var providerMock = new Mock<IAuthenticationProvider>();

        _credentialRepositoryMock.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        var success = await _service.UpdateCredentialUsageAsync(credential, null, result, providerMock.Object);

        Assert.That(success, Is.True);
    }

    [Test]
    public async Task UpdateCredentialUsageAsyncWithRequiredUpdateConflictShouldReturnFalse()
    {
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Oidc,
            ProviderName = "Google",
            ProviderKey = "sub",
            Version = "v1",
            CreatedAt = _timeProvider.GetUtcNow(),
            Status = CredentialStatus.Active,
            LastUsedAt = _timeProvider.GetUtcNow().AddDays(-1)
        };
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded, CredentialUpdateRequirement: CredentialUpdateRequirement.Required);
        var providerMock = new Mock<IAuthenticationProvider>();

        _credentialRepositoryMock.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        var success = await _service.UpdateCredentialUsageAsync(credential, null, result, providerMock.Object);

        Assert.That(success, Is.False);
    }

    [Test]
    public async Task UpdateCredentialUsageAsyncWithBestEffortUpdateExceptionShouldReturnTrue()
    {
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Oidc,
            ProviderName = "Google",
            ProviderKey = "sub",
            Version = "v1",
            CreatedAt = _timeProvider.GetUtcNow(),
            Status = CredentialStatus.Active,
            LastUsedAt = _timeProvider.GetUtcNow().AddDays(-1)
        };
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded, CredentialUpdateRequirement: CredentialUpdateRequirement.BestEffort);
        var providerMock = new Mock<IAuthenticationProvider>();

        _credentialRepositoryMock.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("DB Error"));

        var success = await _service.UpdateCredentialUsageAsync(credential, null, result, providerMock.Object);

        Assert.That(success, Is.True);
    }

    [Test]
    public async Task UpdateCredentialUsageAsyncWithUninitializedProviderTypeInFailurePathShouldReturnTrue()
    {
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = default,
            ProviderName = "broken-provider",
            ProviderKey = "sub",
            Version = "v1",
            CreatedAt = _timeProvider.GetUtcNow(),
            Status = CredentialStatus.Active,
            CredentialValue = "unprotected-secret"
        };
        var result = new AuthenticationResult(
            AuthenticationResultStatus.SucceededWithCredentialUpdate,
            NewCredentialValue: "rotated-secret",
            CredentialUpdateRequirement: CredentialUpdateRequirement.BestEffort);
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);

        _secretProtectorMock.Setup(s => s.Protect("rotated-secret")).Throws(new InvalidOperationException("Protection failed"));

        var success = await _service.UpdateCredentialUsageAsync(credential, null, result, providerMock.Object);

        Assert.That(success, Is.True);
    }

    [Test]
    public async Task UpdateCredentialUsageAsyncWithRequiredUpdateExceptionShouldReturnFalse()
    {
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Oidc,
            ProviderName = "Google",
            ProviderKey = "sub",
            Version = "v1",
            CreatedAt = _timeProvider.GetUtcNow(),
            Status = CredentialStatus.Active,
            LastUsedAt = _timeProvider.GetUtcNow().AddDays(-1)
        };
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded, CredentialUpdateRequirement: CredentialUpdateRequirement.Required);
        var providerMock = new Mock<IAuthenticationProvider>();

        _credentialRepositoryMock.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("DB Error"));

        var success = await _service.UpdateCredentialUsageAsync(credential, null, result, providerMock.Object);

        Assert.That(success, Is.False);
    }

    [Test]
    public void UpdateCredentialUsageAsyncWithOperationCanceledExceptionShouldPropagate()
    {
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Oidc,
            ProviderName = "Google",
            ProviderKey = "sub",
            Version = "v1",
            CreatedAt = _timeProvider.GetUtcNow(),
            Status = CredentialStatus.Active,
            LastUsedAt = _timeProvider.GetUtcNow().AddDays(-1)
        };
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded, CredentialUpdateRequirement: CredentialUpdateRequirement.Required);
        var providerMock = new Mock<IAuthenticationProvider>();

        _credentialRepositoryMock.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new OperationCanceledException());

        Assert.ThrowsAsync<OperationCanceledException>(async () => await _service.UpdateCredentialUsageAsync(credential, null, result, providerMock.Object));
    }

    [Test]
    public async Task UpdateCredentialUsageAsyncWithConsumeConflictShouldAlwaysReturnFalseRegardlessOfRequirement()
    {
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Oidc,
            ProviderName = "Google",
            ProviderKey = "sub",
            Version = "v1",
            CreatedAt = _timeProvider.GetUtcNow(),
            Status = CredentialStatus.Active
        };
        // Consume failure should always be critical, even if requirement is BestEffort.
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded, IsCredentialConsumed: true, CredentialUpdateRequirement: CredentialUpdateRequirement.BestEffort);
        var providerMock = new Mock<IAuthenticationProvider>();

        _credentialRepositoryMock.Setup(r => r.ConsumeCredentialAsync(credential.Id, "v1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        var success = await _service.UpdateCredentialUsageAsync(credential, null, result, providerMock.Object);

        Assert.That(success, Is.False);
    }

    [Test]
    public async Task UpdateCredentialUsageAsyncWithBestEffortProtectionExceptionShouldRestoreOriginalValue()
    {
        var originalCredential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Oidc,
            ProviderName = "Google",
            ProviderKey = "sub",
            Version = "v1",
            CreatedAt = _timeProvider.GetUtcNow(),
            Status = CredentialStatus.Active,
            CredentialValue = "protected-original"
        };
        var unprotectedCredential = new UserCredential
        {
            Id = originalCredential.Id,
            UserId = originalCredential.UserId,
            ProviderType = originalCredential.ProviderType,
            ProviderName = originalCredential.ProviderName,
            ProviderKey = originalCredential.ProviderKey,
            Version = originalCredential.Version,
            CreatedAt = _timeProvider.GetUtcNow(),
            Status = CredentialStatus.Active,
            CredentialValue = "unprotected-original",
            LastUsedAt = _timeProvider.GetUtcNow().AddDays(-1)
        };
        var result = new AuthenticationResult(AuthenticationResultStatus.SucceededWithCredentialUpdate, NewCredentialValue: "new-raw", CredentialUpdateRequirement: CredentialUpdateRequirement.BestEffort);
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);

        _secretProtectorMock.Setup(s => s.Protect("new-raw")).Throws(new InvalidOperationException("Encryption error"));

        await _service.UpdateCredentialUsageAsync(unprotectedCredential, originalCredential, result, providerMock.Object);

        // Verify that UpdateCredentialAsync was called with the original protected value, NOT the plain-text one.
        _credentialRepositoryMock.Verify(r => r.UpdateCredentialAsync(It.Is<UserCredential>(c => c.CredentialValue == "protected-original"), "v1", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task UpdateCredentialUsageAsyncWithNullOriginalCredentialShouldReProtectToAvoidLeak()
    {
        var unprotectedCredential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Oidc,
            ProviderName = "Google",
            ProviderKey = "sub",
            Version = "v1",
            CreatedAt = _timeProvider.GetUtcNow(),
            Status = CredentialStatus.Active,
            CredentialValue = "unprotected-secret",
            LastUsedAt = _timeProvider.GetUtcNow().AddDays(-1)
        };
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded);
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);

        _secretProtectorMock.Setup(s => s.Protect("unprotected-secret")).Returns("re-protected-secret");

        await _service.UpdateCredentialUsageAsync(unprotectedCredential, null, result, providerMock.Object);

        // Verify that UpdateCredentialAsync was called with the re-protected value.
        _credentialRepositoryMock.Verify(r => r.UpdateCredentialAsync(It.Is<UserCredential>(c => c.CredentialValue == "re-protected-secret"), "v1", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task UpdateCredentialUsageAsyncWithNullOriginalAndProtectionFailureShouldCancelUpdate()
    {
        var unprotectedCredential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Oidc,
            ProviderName = "Google",
            ProviderKey = "sub",
            Version = "v1",
            CreatedAt = _timeProvider.GetUtcNow(),
            Status = CredentialStatus.Active,
            CredentialValue = "unprotected-secret",
            LastUsedAt = _timeProvider.GetUtcNow().AddDays(-1)
        };
        // Status SucceededWithCredentialUpdate triggers the try-catch for protection.
        var result = new AuthenticationResult(AuthenticationResultStatus.SucceededWithCredentialUpdate, NewCredentialValue: "new-raw", CredentialUpdateRequirement: CredentialUpdateRequirement.BestEffort);
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);

        // Both Protect calls fail.
        _secretProtectorMock.Setup(s => s.Protect(It.IsAny<string>())).Throws(new InvalidOperationException("Encryption error"));

        await _service.UpdateCredentialUsageAsync(unprotectedCredential, null, result, providerMock.Object);

        // Verify that UpdateCredentialAsync was NEVER called because we couldn't guarantee protection.
        _credentialRepositoryMock.Verify(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task UpdateCredentialUsageAsyncWithRequiredProtectionExceptionShouldReturnFalse()
    {
        var originalCredential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Oidc,
            ProviderName = "Google",
            ProviderKey = "sub",
            Version = "v1",
            CreatedAt = _timeProvider.GetUtcNow(),
            Status = CredentialStatus.Active,
            CredentialValue = "protected-original"
        };
        var unprotectedCredential = new UserCredential
        {
            Id = originalCredential.Id,
            UserId = originalCredential.UserId,
            ProviderType = originalCredential.ProviderType,
            ProviderName = originalCredential.ProviderName,
            ProviderKey = originalCredential.ProviderKey,
            Version = originalCredential.Version,
            CreatedAt = _timeProvider.GetUtcNow(),
            Status = CredentialStatus.Active,
            CredentialValue = "unprotected-original",
            LastUsedAt = _timeProvider.GetUtcNow().AddDays(-1)
        };
        var result = new AuthenticationResult(AuthenticationResultStatus.SucceededWithCredentialUpdate, NewCredentialValue: "new-raw", CredentialUpdateRequirement: CredentialUpdateRequirement.Required);
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);

        _secretProtectorMock.Setup(s => s.Protect("new-raw")).Throws(new InvalidOperationException("Encryption error"));

        var success = await _service.UpdateCredentialUsageAsync(unprotectedCredential, originalCredential, result, providerMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(success, Is.False);
            _credentialRepositoryMock.Verify(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task UpdateCredentialUsageAsyncWithProtectedProviderAndNoValueOrOriginalShouldReturnFalseToAvoidWipe()
    {
        var unprotectedCredential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Oidc,
            ProviderName = "Google",
            ProviderKey = "sub",
            Version = "v1",
            CreatedAt = _timeProvider.GetUtcNow(),
            Status = CredentialStatus.Active,
            CredentialValue = null, // No value provided
            LastUsedAt = _timeProvider.GetUtcNow().AddDays(-1)
        };
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded);
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);

        // We are NOT passing originalCredential.
        var success = await _service.UpdateCredentialUsageAsync(unprotectedCredential, null, result, providerMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(success, Is.False);
            _credentialRepositoryMock.Verify(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task ResolveAsyncWithEmptyProviderKeyShouldGenerateNewOne()
    {
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey((ProviderType)"MOCK", "Mock"));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<Guid>())).Returns("");

        await _service.ResolveAsync(Guid.NewGuid(), new Mock<IAuthenticationAssertion>().Object, providerMock.Object);

        _credentialRepositoryMock.Verify(r => r.GetCredentialForUserAsync(It.IsAny<Guid>(), It.IsAny<ProviderType>(), "Mock", It.Is<string>(s => !string.IsNullOrEmpty(s)), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task ResolveAsyncWithCryptographicExceptionShouldSetUnprotectFailed()
    {
        var userId = Guid.NewGuid();
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.Oidc,
            ProviderName = "Google",
            ProviderKey = "sub",
            Version = "v1",
            CreatedAt = _timeProvider.GetUtcNow(),
            Status = CredentialStatus.Active,
            CredentialValue = "bad-value"
        };

        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<Guid>())).Returns("sub");
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);
        providerMock.Setup(p => p.TypicalCredentialLength).Returns(256);

        var assertionMock = new Mock<IAuthenticationAssertion>();
        assertionMock.Setup(a => a.ProviderIdentity).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));

        _secretProtectorMock.Setup(s => s.Unprotect("bad-value")).Throws(new System.Security.Cryptography.CryptographicException());
        var logger = new RecordingLogger<CredentialService>();
        var service = new CredentialService(
            _repositoryMock.Object,
            _credentialRepositoryMock.Object,
            _secretProtectorMock.Object,
            new NullTransactionProvider(),
            new CredentialServiceDependencies(TimeProvider: _timeProvider, Logger: logger));

        var (_, resolvedCredential, _, unprotectFailed) = await service.ResolveAsync(userId, assertionMock.Object, providerMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(unprotectFailed, Is.True);
            Assert.That(resolvedCredential?.CredentialValue, Is.Null);
            Assert.That(logger.Entries, Has.Some.Matches<LogEntry>(entry =>
                entry.Level == LogLevel.Warning
                && entry.Exception is System.Security.Cryptography.CryptographicException
                && entry.Message.Contains("Credential value unprotection failed", StringComparison.Ordinal)
                && entry.Message.Contains($"CredentialId={credential.Id}", StringComparison.Ordinal)));
        }
    }

    [Test]
    public async Task ResolveAsyncWithCryptographicExceptionOnDummyValueShouldNotSetUnprotectFailed()
    {
        // When credential is null, we use a dummy value.
        // If unprotecting the dummy value fails, we do NOT set unprotectFailed to true
        // to avoid leaking whether the user/credential exists via side channels.

        var userId = Guid.NewGuid();
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(It.IsAny<Guid>(), It.IsAny<ProviderType>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((UserCredential?)null);

        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<Guid>())).Returns("sub");
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);
        providerMock.Setup(p => p.TypicalCredentialLength).Returns(256);

        var assertionMock = new Mock<IAuthenticationAssertion>();
        assertionMock.Setup(a => a.ProviderIdentity).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));

        // First call to generate the dummy and protect it.
        _secretProtectorMock.Setup(s => s.Protect(It.IsAny<string>())).Returns("protected-dummy");
        // Mock unprotect to throw.
        _secretProtectorMock.Setup(s => s.Unprotect("protected-dummy")).Throws<System.Security.Cryptography.CryptographicException>();
        var logger = new RecordingLogger<CredentialService>();
        var service = new CredentialService(
            _repositoryMock.Object,
            _credentialRepositoryMock.Object,
            _secretProtectorMock.Object,
            new NullTransactionProvider(),
            new CredentialServiceDependencies(TimeProvider: _timeProvider, Logger: logger));

        var (_, resolvedCredential, originalCredential, unprotectFailed) = await service.ResolveAsync(userId, assertionMock.Object, providerMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(unprotectFailed, Is.False);
            Assert.That(resolvedCredential, Is.Null);
            Assert.That(originalCredential, Is.Null);
            Assert.That(logger.Entries, Has.Some.Matches<LogEntry>(entry =>
                entry.Level == LogLevel.Debug
                && entry.Exception is System.Security.Cryptography.CryptographicException
                && entry.Message.Contains("Dummy credential unprotection failed", StringComparison.Ordinal)
                && entry.Message.Contains("ProviderName=Google", StringComparison.Ordinal)));
        }
    }

    [Test]
    public async Task ResolveAsyncWithNullCredentialValueShouldNotUnprotect()
    {
        var userId = Guid.NewGuid();
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.Oidc,
            ProviderName = "Google",
            ProviderKey = "sub",
            Version = "v1",
            CreatedAt = _timeProvider.GetUtcNow(),
            Status = CredentialStatus.Active,
            CredentialValue = null
        };

        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<Guid>())).Returns("sub");
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);

        var assertionMock = new Mock<IAuthenticationAssertion>();
        assertionMock.Setup(a => a.ProviderIdentity).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));

        var (_, resolvedCredential, _, unprotectFailed) = await _service.ResolveAsync(userId, assertionMock.Object, providerMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(unprotectFailed, Is.False);
            Assert.That(resolvedCredential?.CredentialValue, Is.Null);
        }
    }

    [Test]
    public async Task LinkCredentialAsyncShouldCreateCredential()
    {
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, DisplayEmail = "test@example.com" };
        var assertionMock = new Mock<IAuthenticationAssertion>();
        assertionMock.Setup(a => a.ProviderIdentity).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));

        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.GetProviderKey(assertionMock.Object, userId)).Returns("new-key");
        providerMock.Setup(p => p.PrepareCredentialValue(assertionMock.Object, "raw")).Returns("prepared");
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, "Google", "new-key", It.IsAny<CancellationToken>())).ReturnsAsync((IUser?)null);
        _secretProtectorMock.Setup(s => s.Protect("prepared")).Returns("protected-prepared");

        const string credentialMetadata = "{\"LastUsedStep\":123}";
        var beforeLink = _timeProvider.GetUtcNow();
        await _service.LinkCredentialAsync(userId, assertionMock.Object, providerMock.Object, "raw", credentialMetadata);
        var afterLink = _timeProvider.GetUtcNow();

        _credentialRepositoryMock.Verify(r => r.CreateOrReplaceCredentialAsync(It.Is<UserCredential>(c =>
            c.UserId == userId &&
            c.ProviderKey == "new-key" &&
            c.CredentialValue == "protected-prepared" &&
            c.Metadata == credentialMetadata &&
            c.CreatedAt >= beforeLink &&
            c.CreatedAt <= afterLink &&
            c.Status == CredentialStatus.Active &&
            c.UpdatedAt == null &&
            c.ExpiresAt == null &&
            c.RevokedAt == null), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task ResolveAsyncShouldPreserveLifecycleFieldsOnUnprotectedCredential()
    {
        var userId = Guid.NewGuid();
        var createdAt = _timeProvider.GetUtcNow().AddDays(-7);
        var updatedAt = _timeProvider.GetUtcNow().AddDays(-2);
        var expiresAt = _timeProvider.GetUtcNow().AddDays(1);
        var credential = CreateCredential(
            userId,
            createdAt: createdAt,
            updatedAt: updatedAt,
            expiresAt: expiresAt,
            status: CredentialStatus.Active,
            purpose: "email-login",
            credentialValue: "protected(token)");

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "test@example.com" });
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var providerMock = CreateProviderMock();

        var (_, resolvedCredential, _, _) = await _service.ResolveAsync(userId, new Mock<IAuthenticationAssertion>().Object, providerMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(resolvedCredential?.CreatedAt, Is.EqualTo(createdAt));
            Assert.That(resolvedCredential?.UpdatedAt, Is.EqualTo(updatedAt));
            Assert.That(resolvedCredential?.ExpiresAt, Is.EqualTo(expiresAt));
            Assert.That(resolvedCredential?.RevokedAt, Is.Null);
            Assert.That(resolvedCredential?.Status, Is.EqualTo(CredentialStatus.Active));
            Assert.That(resolvedCredential?.Purpose, Is.EqualTo("email-login"));
            Assert.That(resolvedCredential?.CredentialValue, Is.EqualTo("token"));
        }
    }

    [Test]
    public async Task ResolveAsyncWithExpiredCredentialShouldReturnNullCredential()
    {
        var credential = CreateCredential(
            Guid.NewGuid(),
            expiresAt: _timeProvider.GetUtcNow().AddSeconds(-1),
            credentialValue: "protected(token)");

        var resolvedCredential = await ResolveCredentialAsync(credential);

        Assert.That(resolvedCredential, Is.Null);
    }

    [Test]
    public async Task ResolveAsyncWithRevokedCredentialShouldReturnNullCredential()
    {
        var credential = CreateCredential(
            Guid.NewGuid(),
            revokedAt: _timeProvider.GetUtcNow(),
            credentialValue: "protected(token)");

        var resolvedCredential = await ResolveCredentialAsync(credential);

        Assert.That(resolvedCredential, Is.Null);
    }

    [Test]
    public async Task ResolveAsyncWithNonActiveCredentialShouldReturnNullCredential()
    {
        var credential = CreateCredential(
            Guid.NewGuid(),
            status: CredentialStatus.Revoked,
            credentialValue: "protected(token)");

        var resolvedCredential = await ResolveCredentialAsync(credential);

        Assert.That(resolvedCredential, Is.Null);
    }

    [Test]
    public async Task UpdateCredentialUsageAsyncWithMetadataChangeShouldSetUpdatedAt()
    {
        var credential = CreateCredential(Guid.NewGuid());
        credential.Metadata = "old";
        credential.LastUsedAt = _timeProvider.GetUtcNow();
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded, NewMetadata: "new");
        var providerMock = new Mock<IAuthenticationProvider>();

        _credentialRepositoryMock.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        await _service.UpdateCredentialUsageAsync(credential, null, result, providerMock.Object);

        _credentialRepositoryMock.Verify(r => r.UpdateCredentialAsync(It.Is<UserCredential>(c =>
            c.Metadata == "new" &&
            c.UpdatedAt != null), "v1", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task UpdateCredentialUsageAsyncWithNoChangesShouldNotSetUpdatedAtOrCallRepository()
    {
        var credential = CreateCredential(Guid.NewGuid());
        credential.LastUsedAt = _timeProvider.GetUtcNow();
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded);
        var providerMock = new Mock<IAuthenticationProvider>();

        await _service.UpdateCredentialUsageAsync(credential, null, result, providerMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(credential.UpdatedAt, Is.Null);
            _credentialRepositoryMock.Verify(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task UpdateCredentialUsageAsyncWithUnchangedMetadataShouldNotCallRepository()
    {
        var credential = CreateCredential(Guid.NewGuid());
        credential.Metadata = "unchanged";
        credential.LastUsedAt = _timeProvider.GetUtcNow();
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded, NewMetadata: "unchanged");
        var providerMock = new Mock<IAuthenticationProvider>();

        await _service.UpdateCredentialUsageAsync(credential, null, result, providerMock.Object);

        _credentialRepositoryMock.Verify(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public void LinkCredentialAsyncWithEmptyUserIdShouldThrow()
    {
        Assert.ThrowsAsync<ArgumentException>(() => _service.LinkCredentialAsync(Guid.Empty, new Mock<IAuthenticationAssertion>().Object, new Mock<IAuthenticationProvider>().Object));
    }

    [Test]
    public async Task LinkCredentialAsyncWithMissingUserShouldFail()
    {
        var userId = Guid.NewGuid();
        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>())).ReturnsAsync((IUser?)null);
        var result = await _service.LinkCredentialAsync(userId, new Mock<IAuthenticationAssertion>().Object, new Mock<IAuthenticationProvider>().Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
        }
    }

    [Test]
    public async Task LinkCredentialAsyncWithEmptyProviderKeyShouldFail()
    {
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, DisplayEmail = "test@example.com" };
        var assertionMock = new Mock<IAuthenticationAssertion>();
        assertionMock.Setup(a => a.ProviderIdentity).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.Setup(p => p.GetProviderKey(assertionMock.Object, userId)).Returns("");

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>())).ReturnsAsync(user);

        var result = await _service.LinkCredentialAsync(userId, assertionMock.Object, providerMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidProviderKey));
        }
    }

    [Test]
    public async Task LinkCredentialAsyncWithDuplicateKeyShouldFail()
    {
        var userId = Guid.NewGuid();
        var otherUserId = Guid.NewGuid();
        var user = new User { Id = userId, DisplayEmail = "test@example.com" };
        var assertionMock = new Mock<IAuthenticationAssertion>();
        assertionMock.Setup(a => a.ProviderIdentity).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.GetProviderKey(assertionMock.Object, userId)).Returns("key");

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, "Google", "key", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = otherUserId, DisplayEmail = "other@example.com" });

        var result = await _service.LinkCredentialAsync(userId, assertionMock.Object, providerMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.AlreadyLinkedToOther));
        }
    }

    [Test]
    public async Task LinkCredentialAsyncWithDuplicateKeyForSameUserShouldFail()
    {
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, DisplayEmail = "test@example.com" };
        var assertionMock = new Mock<IAuthenticationAssertion>();
        assertionMock.Setup(a => a.ProviderIdentity).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.GetProviderKey(assertionMock.Object, userId)).Returns("key");

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, "Google", "key", It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var result = await _service.LinkCredentialAsync(userId, assertionMock.Object, providerMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.AlreadyLinkedToSelf));
        }
    }

    [Test]
    public async Task LinkCredentialAsyncWithDuplicateKeyForSameUserLocalShouldFail()
    {
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, DisplayEmail = "test@example.com" };
        var assertionMock = new Mock<IAuthenticationAssertion>();
        assertionMock.Setup(a => a.ProviderIdentity).Returns(AuthenticationProviderKey.Local);
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(AuthenticationProviderKey.Local);
        providerMock.Setup(p => p.GetProviderKey(assertionMock.Object, userId)).Returns("key");

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Local, AuthenticationProviderKey.Local.Name, "key", It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var result = await _service.LinkCredentialAsync(userId, assertionMock.Object, providerMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.AlreadyLinkedToSelf));
        }
    }

    [Test]
    public void UpdateCredentialUsageAsyncWithNullUnprotectedCredentialShouldThrow()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.ThrowsAsync<ArgumentNullException>(() => _service.UpdateCredentialUsageAsync(null!, null, new AuthenticationResult(AuthenticationResultStatus.Succeeded), new Mock<IAuthenticationProvider>().Object));
    }

    [Test]
    public void UpdateCredentialUsageAsyncWithNullResultShouldThrow()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.ThrowsAsync<ArgumentNullException>(() => _service.UpdateCredentialUsageAsync(new UserCredential { Id = Guid.NewGuid(), UserId = Guid.NewGuid(), ProviderType = ProviderType.Local, ProviderName = "L", ProviderKey = "K", Version = "v1", CreatedAt = _timeProvider.GetUtcNow(), Status = CredentialStatus.Active }, null, null!, new Mock<IAuthenticationProvider>().Object));
    }

    [Test]
    public void UpdateCredentialUsageAsyncWithNullProviderShouldThrow()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.ThrowsAsync<ArgumentNullException>(() => _service.UpdateCredentialUsageAsync(new UserCredential { Id = Guid.NewGuid(), UserId = Guid.NewGuid(), ProviderType = ProviderType.Local, ProviderName = "L", ProviderKey = "K", Version = "v1", CreatedAt = _timeProvider.GetUtcNow(), Status = CredentialStatus.Active }, null, new AuthenticationResult(AuthenticationResultStatus.Succeeded), null!));
    }

    [Test]
    public void ResolveAsyncWithEmailAndNullAssertionShouldThrow()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.ThrowsAsync<ArgumentNullException>(() => _service.ResolveAsync(new AuthenticationContext("e"), null!, new Mock<IAuthenticationProvider>().Object));
    }

    [Test]
    public void ResolveAsyncWithEmailAndNullProviderShouldThrow()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.ThrowsAsync<ArgumentNullException>(() => _service.ResolveAsync(new AuthenticationContext("e"), new Mock<IAuthenticationAssertion>().Object, null!));
    }

    [Test]
    public void ResolveAsyncWithIdAndNullAssertionShouldThrow()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.ThrowsAsync<ArgumentNullException>(() => _service.ResolveAsync(Guid.NewGuid(), null!, new Mock<IAuthenticationProvider>().Object));
    }

    [Test]
    public void ResolveAsyncWithIdAndNullProviderShouldThrow()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.ThrowsAsync<ArgumentNullException>(() => _service.ResolveAsync(Guid.NewGuid(), new Mock<IAuthenticationAssertion>().Object, null!));
    }

    [Test]
    public void LinkCredentialAsyncWithNullAssertionShouldThrow()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.ThrowsAsync<ArgumentNullException>(() => _service.LinkCredentialAsync(Guid.NewGuid(), null!, new Mock<IAuthenticationProvider>().Object));
    }

    [Test]
    public void LinkCredentialAsyncWithNullProviderShouldThrow()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.ThrowsAsync<ArgumentNullException>(() => _service.LinkCredentialAsync(Guid.NewGuid(), new Mock<IAuthenticationAssertion>().Object, null!));
    }

    [Test]
    public void ConstructorShouldThrowOnNullRepository()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new CredentialService(null!, _credentialRepositoryMock.Object, _secretProtectorMock.Object, new NullTransactionProvider()));
    }

    [Test]
    public void ConstructorShouldThrowOnNullCredentialRepository()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new CredentialService(_repositoryMock.Object, null!, _secretProtectorMock.Object, new NullTransactionProvider()));
    }

    [Test]
    public void ConstructorShouldThrowOnNullSecretProtector()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new CredentialService(_repositoryMock.Object, _credentialRepositoryMock.Object, null!, new NullTransactionProvider()));
    }

    [Test]
    public void ConstructorShouldThrowOnNullTransactionProvider()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new CredentialService(_repositoryMock.Object, _credentialRepositoryMock.Object, _secretProtectorMock.Object, null!));
    }

    [Test]
    public void ConstructorShouldThrowOnNullDependencies()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new CredentialService(_repositoryMock.Object, _credentialRepositoryMock.Object, _secretProtectorMock.Object, new NullTransactionProvider(), null!));
    }

    private async Task<UserCredential?> ResolveCredentialAsync(UserCredential credential)
    {
        _repositoryMock.Setup(r => r.GetUserByIdAsync(credential.UserId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = credential.UserId, DisplayEmail = "test@example.com" });
        _credentialRepositoryMock.Setup(r => r.GetCredentialForUserAsync(credential.UserId, ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var providerMock = CreateProviderMock();
        var (_, resolvedCredential, _, _) = await _service.ResolveAsync(credential.UserId, new Mock<IAuthenticationAssertion>().Object, providerMock.Object);

        return resolvedCredential;
    }

    private static Mock<IAuthenticationProvider> CreateProviderMock()
    {
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<Guid>())).Returns("sub");
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);
        return providerMock;
    }

    private UserCredential CreateCredential(
        Guid userId,
        DateTimeOffset? createdAt = null,
        DateTimeOffset? updatedAt = null,
        DateTimeOffset? expiresAt = null,
        DateTimeOffset? revokedAt = null,
        CredentialStatus status = CredentialStatus.Active,
        string? purpose = null,
        string? credentialValue = null)
    {
        return new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.Oidc,
            ProviderName = "Google",
            ProviderKey = "sub",
            Version = "v1",
            CreatedAt = createdAt ?? _timeProvider.GetUtcNow(),
            UpdatedAt = updatedAt,
            ExpiresAt = expiresAt,
            RevokedAt = revokedAt,
            Status = status,
            Purpose = purpose,
            CredentialValue = credentialValue
        };
    }

    private sealed class NonTenantUser : IUser
    {
        public required Guid Id { get; init; }
        public required string DisplayEmail { get; set; }
        public string? Name { get; set; }
        public UserAccountState AccountState { get; set; } = UserAccountState.Active;
        public DateTimeOffset? EmailVerifiedAt { get; set; }
    }
}
