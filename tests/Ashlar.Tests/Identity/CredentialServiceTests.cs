using Ashlar.Identity;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.Providers.External;
using Ashlar.Security.Encryption;
using Moq;

namespace Ashlar.Tests.Identity;

public class CredentialServiceTests
{
    private Mock<IIdentityRepository> _repositoryMock;
    private Mock<ISecretProtector> _secretProtectorMock;
    private CredentialService _service;

    [SetUp]
    public void SetUp()
    {
        _repositoryMock = new Mock<IIdentityRepository>();
        _secretProtectorMock = new Mock<ISecretProtector>();

        _secretProtectorMock.Setup(s => s.Protect(It.IsAny<string>())).Returns<string>(s => $"protected({s})");
        _secretProtectorMock.Setup(s => s.Unprotect(It.IsAny<string>())).Returns<string>(s => s.StartsWith("protected(", StringComparison.Ordinal) ? s[10..^1] : s);

        _service = new CredentialService(_repositoryMock.Object, _secretProtectorMock.Object);
    }

    [Test]
    public async Task ResolveAsyncShouldReturnUnprotectedCredential()
    {
        var email = "test@example.com";
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = email };
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.Oidc,
            ProviderName = "Google",
            ProviderKey = "sub",
            Version = "v1",
            CredentialValue = "protected(token)"
        };

        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
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
            CredentialValue = "value"
        };
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(AuthenticationProviderKey.Local);
        providerMock.Setup(p => p.ProtectsCredentials).Returns(false);

        _repositoryMock.Setup(r => r.GetUserByIdAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = credential.UserId, Email = "test@example.com" });
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(It.IsAny<Guid>(), It.IsAny<ProviderType>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var (_, resolvedCredential, _, _) = await _service.ResolveAsync(credential.UserId, new Mock<IAuthenticationAssertion>().Object, providerMock.Object);

        Assert.That(resolvedCredential?.CredentialValue, Is.EqualTo("value"));
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
            Metadata = "old",
            LastUsedAt = DateTimeOffset.UtcNow
        };
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded, NewMetadata: "new");
        var providerMock = new Mock<IAuthenticationProvider>();

        await _service.UpdateCredentialUsageAsync(credential, null, result, providerMock.Object);

        _repositoryMock.Verify(r => r.UpdateCredentialAsync(It.Is<UserCredential>(c => c.Metadata == "new"), "v1", It.IsAny<CancellationToken>()), Times.Once);
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
            Version = "v1"
        };
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded, IsCredentialConsumed: true);
        var providerMock = new Mock<IAuthenticationProvider>();

        _repositoryMock.Setup(r => r.ConsumeCredentialAsync(credential.Id, "v1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var consumed = await _service.UpdateCredentialUsageAsync(credential, null, result, providerMock.Object);

        Assert.That(consumed, Is.True);
        _repositoryMock.Verify(r => r.ConsumeCredentialAsync(credential.Id, "v1", It.IsAny<CancellationToken>()), Times.Once);
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
            Version = "v1"
        };
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded, IsCredentialConsumed: true);
        var providerMock = new Mock<IAuthenticationProvider>();

        _repositoryMock.Setup(r => r.ConsumeCredentialAsync(credential.Id, "v1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        var consumed = await _service.UpdateCredentialUsageAsync(credential, null, result, providerMock.Object);

        Assert.That(consumed, Is.False);
    }

    [Test]
    public Task UpdateCredentialUsageAsyncWithExceptionShouldNotThrow()
    {
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Oidc,
            ProviderName = "Google",
            ProviderKey = "sub",
            Version = "v1",
            LastUsedAt = DateTimeOffset.UtcNow.AddDays(-1)
        };
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded);
        var providerMock = new Mock<IAuthenticationProvider>();

        _repositoryMock.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("DB Error"));

        Assert.DoesNotThrowAsync(async () => await _service.UpdateCredentialUsageAsync(credential, null, result, providerMock.Object));
        return Task.CompletedTask;
    }

    [Test]
    public async Task ResolveAsyncWithEmptyProviderKeyShouldGenerateNewOne()
    {
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey((ProviderType)"MOCK", "Mock"));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<Guid>())).Returns("");

        await _service.ResolveAsync(Guid.NewGuid(), new Mock<IAuthenticationAssertion>().Object, providerMock.Object);

        _repositoryMock.Verify(r => r.GetCredentialForUserAsync(It.IsAny<Guid>(), It.IsAny<ProviderType>(), "Mock", It.Is<string>(s => !string.IsNullOrEmpty(s)), It.IsAny<CancellationToken>()), Times.Once);
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
            CredentialValue = "bad-value"
        };

        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<Guid>())).Returns("sub");
        providerMock.Setup(p => p.ProtectsCredentials).Returns(true);
        providerMock.Setup(p => p.TypicalCredentialLength).Returns(256);

        var assertionMock = new Mock<IAuthenticationAssertion>();
        assertionMock.Setup(a => a.ProviderIdentity).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));

        _secretProtectorMock.Setup(s => s.Unprotect("bad-value")).Throws(new System.Security.Cryptography.CryptographicException());

        var (_, resolvedCredential, _, unprotectFailed) = await _service.ResolveAsync(userId, assertionMock.Object, providerMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(unprotectFailed, Is.True);
            Assert.That(resolvedCredential?.CredentialValue, Is.Null);
        }
    }

    [Test]
    public async Task ResolveAsyncWithCryptographicExceptionOnDummyValueShouldNotSetUnprotectFailed()
    {
        // When credential is null, we use a dummy value.
        // If unprotecting the dummy value fails, we do NOT set unprotectFailed to true
        // to avoid leaking whether the user/credential exists via side channels.

        var userId = Guid.NewGuid();
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(It.IsAny<Guid>(), It.IsAny<ProviderType>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
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

        var (_, resolvedCredential, originalCredential, unprotectFailed) = await _service.ResolveAsync(userId, assertionMock.Object, providerMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(unprotectFailed, Is.False);
            Assert.That(resolvedCredential, Is.Null);
            Assert.That(originalCredential, Is.Null);
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
            CredentialValue = null
        };

        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Oidc, "Google", "sub", It.IsAny<CancellationToken>()))
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
        var user = new User { Id = userId, Email = "test@example.com" };
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

        await _service.LinkCredentialAsync(userId, assertionMock.Object, providerMock.Object, "raw");

        _repositoryMock.Verify(r => r.CreateCredentialAsync(It.Is<UserCredential>(c =>
            c.UserId == userId &&
            c.ProviderKey == "new-key" &&
            c.CredentialValue == "protected-prepared"), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public void LinkCredentialAsyncWithEmptyUserIdShouldThrow()
    {
        Assert.ThrowsAsync<ArgumentException>(() => _service.LinkCredentialAsync(Guid.Empty, new Mock<IAuthenticationAssertion>().Object, new Mock<IAuthenticationProvider>().Object));
    }

    [Test]
    public void LinkCredentialAsyncWithMissingUserShouldThrow()
    {
        var userId = Guid.NewGuid();
        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>())).ReturnsAsync((IUser?)null);
        Assert.ThrowsAsync<InvalidOperationException>(() => _service.LinkCredentialAsync(userId, new Mock<IAuthenticationAssertion>().Object, new Mock<IAuthenticationProvider>().Object));
    }

    [Test]
    public void LinkCredentialAsyncWithEmptyProviderKeyShouldThrow()
    {
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = "test@example.com" };
        var assertionMock = new Mock<IAuthenticationAssertion>();
        assertionMock.Setup(a => a.ProviderIdentity).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.Setup(p => p.GetProviderKey(assertionMock.Object, userId)).Returns("");

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>())).ReturnsAsync(user);

        Assert.ThrowsAsync<InvalidOperationException>(() => _service.LinkCredentialAsync(userId, assertionMock.Object, providerMock.Object));
    }

    [Test]
    public void LinkCredentialAsyncWithDuplicateKeyShouldThrow()
    {
        var userId = Guid.NewGuid();
        var otherUserId = Guid.NewGuid();
        var user = new User { Id = userId, Email = "test@example.com" };
        var assertionMock = new Mock<IAuthenticationAssertion>();
        assertionMock.Setup(a => a.ProviderIdentity).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.GetProviderKey(assertionMock.Object, userId)).Returns("key");

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, "Google", "key", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = otherUserId, Email = "other@example.com" });

        var ex = Assert.ThrowsAsync<InvalidOperationException>(() => _service.LinkCredentialAsync(userId, assertionMock.Object, providerMock.Object));
        Assert.That(ex.Message, Does.Contain("already linked to another user"));
    }

    [Test]
    public void LinkCredentialAsyncWithDuplicateKeyForSameUserShouldThrow()
    {
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = "test@example.com" };
        var assertionMock = new Mock<IAuthenticationAssertion>();
        assertionMock.Setup(a => a.ProviderIdentity).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        providerMock.Setup(p => p.GetProviderKey(assertionMock.Object, userId)).Returns("key");

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, "Google", "key", It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var ex = Assert.ThrowsAsync<InvalidOperationException>(() => _service.LinkCredentialAsync(userId, assertionMock.Object, providerMock.Object));
        Assert.That(ex.Message, Does.Contain("already linked to this user"));
    }

    [Test]
    public void LinkCredentialAsyncWithDuplicateKeyForSameUserLocalShouldThrowSpecificMessage()
    {
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = "test@example.com" };
        var assertionMock = new Mock<IAuthenticationAssertion>();
        assertionMock.Setup(a => a.ProviderIdentity).Returns(AuthenticationProviderKey.Local);
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(AuthenticationProviderKey.Local);
        providerMock.Setup(p => p.GetProviderKey(assertionMock.Object, userId)).Returns("key");

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Local, AuthenticationProviderKey.Local.Name, "key", It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var ex = Assert.ThrowsAsync<InvalidOperationException>(() => _service.LinkCredentialAsync(userId, assertionMock.Object, providerMock.Object));
        Assert.That(ex.Message, Is.EqualTo("A local password is already linked to this user."));
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
        Assert.ThrowsAsync<ArgumentNullException>(() => _service.UpdateCredentialUsageAsync(new UserCredential { Id = Guid.NewGuid(), UserId = Guid.NewGuid(), ProviderType = ProviderType.Local, ProviderName = "L", ProviderKey = "K", Version = "v1" }, null, null!, new Mock<IAuthenticationProvider>().Object));
    }

    [Test]
    public void UpdateCredentialUsageAsyncWithNullProviderShouldThrow()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.ThrowsAsync<ArgumentNullException>(() => _service.UpdateCredentialUsageAsync(new UserCredential { Id = Guid.NewGuid(), UserId = Guid.NewGuid(), ProviderType = ProviderType.Local, ProviderName = "L", ProviderKey = "K", Version = "v1" }, null, new AuthenticationResult(AuthenticationResultStatus.Succeeded), null!));
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
        Assert.Throws<ArgumentNullException>(() => _ = new CredentialService(null!, _secretProtectorMock.Object));
    }

    [Test]
    public void ConstructorShouldThrowOnNullSecretProtector()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new CredentialService(_repositoryMock.Object, null!));
    }
}
