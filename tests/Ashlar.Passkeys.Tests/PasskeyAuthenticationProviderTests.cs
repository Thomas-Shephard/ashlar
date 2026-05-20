using System.Text.Json;
using Microsoft.Extensions.Options;
using Moq;

namespace Ashlar.Passkeys.Tests;

internal sealed class PasskeyAuthenticationProviderTests
{
    [Test]
    public void ProviderPropertiesShouldExposePasskeyProviderBehavior()
    {
        var provider = new PasskeyAuthenticationProvider(Options.Create(new PasskeyOptions()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.Key, Is.EqualTo(AuthenticationProviderKey.Passkey));
            Assert.That(provider.ProtectsCredentials, Is.False);
            Assert.That(provider.TypicalCredentialLength, Is.Zero);
            Assert.That(provider.PrepareCredentialValue(new PasskeyAssertion("cred", 1), "raw"), Is.EqualTo("raw"));
        }
    }

    [Test]
    public void PasskeyAssertionShouldExposeDefaultAndCustomProviderKeys()
    {
        var defaultAssertion = new PasskeyAssertion("default", 1);
        var customProvider = new AuthenticationProviderKey(ProviderType.Passkey, "custom-passkey");
        var customAssertion = new PasskeyAssertion("custom", 2, true, customProvider);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(defaultAssertion.ProviderIdentity, Is.EqualTo(AuthenticationProviderKey.Passkey));
            Assert.That(defaultAssertion.CredentialKey, Is.EqualTo("default"));
            Assert.That(customAssertion.ProviderIdentity, Is.EqualTo(customProvider));
            Assert.That(customAssertion.CredentialKey, Is.EqualTo("custom"));
        }
    }

    [Test]
    public void GetProviderKeyShouldReturnCredentialIdForPasskeyAssertions()
    {
        var provider = new PasskeyAuthenticationProvider(Options.Create(new PasskeyOptions()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.GetProviderKey(new PasskeyAssertion("cred", 1), Guid.NewGuid()), Is.EqualTo("cred"));
            Assert.That(provider.GetProviderKey(new Mock<IAuthenticationAssertion>().Object, Guid.NewGuid()), Is.Empty);
        }
    }

    [Test]
    public async Task AuthenticateAsyncShouldUpdateSignCount()
    {
        var provider = new PasskeyAuthenticationProvider(Options.Create(new PasskeyOptions()));
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Passkey,
            ProviderName = "PASSKEY",
            ProviderKey = "cred",
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            Metadata = JsonSerializer.Serialize(new PasskeyCredentialMetadata { DisplayName = "Laptop", PublicKey = "pk", SignCount = 1 })
        };

        var result = await provider.AuthenticateAsync(new PasskeyAssertion("cred", 2, true), credential);

        Assert.That(result.Status, Is.EqualTo(AuthenticationResultStatus.SucceededWithCredentialUpdate));
        var metadata = JsonSerializer.Deserialize<PasskeyCredentialMetadata>(result.NewMetadata!, PasskeyJson.Options);
        Assert.That(metadata!.SignCount, Is.EqualTo(2));
    }

    [Test]
    public async Task AuthenticateAsyncShouldRejectLowerSignCount()
    {
        var provider = new PasskeyAuthenticationProvider(Options.Create(new PasskeyOptions()));
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Passkey,
            ProviderName = "PASSKEY",
            ProviderKey = "cred",
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            Metadata = JsonSerializer.Serialize(new PasskeyCredentialMetadata { DisplayName = "Laptop", PublicKey = "pk", SignCount = 5 })
        };

        var result = await provider.AuthenticateAsync(new PasskeyAssertion("cred", 4), credential);

        Assert.That(result.Status, Is.EqualTo(AuthenticationResultStatus.Failed));
    }

    [Test]
    public async Task AuthenticateAsyncShouldRejectEqualSignCountWhenCounterIsActive()
    {
        var provider = new PasskeyAuthenticationProvider(Options.Create(new PasskeyOptions()));
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Passkey,
            ProviderName = "PASSKEY",
            ProviderKey = "cred",
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            Metadata = JsonSerializer.Serialize(new PasskeyCredentialMetadata { DisplayName = "Laptop", PublicKey = "pk", SignCount = 5 })
        };

        var result = await provider.AuthenticateAsync(new PasskeyAssertion("cred", 5), credential);

        Assert.That(result.Status, Is.EqualTo(AuthenticationResultStatus.Failed));
    }

    [Test]
    public async Task AuthenticateAsyncShouldAllowEqualZeroSignCount()
    {
        var provider = new PasskeyAuthenticationProvider(Options.Create(new PasskeyOptions()));
        var credential = CreateCredential(signCount: 0);

        var result = await provider.AuthenticateAsync(new PasskeyAssertion("cred", 0), credential);

        Assert.That(result.Status, Is.EqualTo(AuthenticationResultStatus.SucceededWithCredentialUpdate));
    }

    [Test]
    public async Task AuthenticateAsyncShouldRejectMissingCredentialOrMetadata()
    {
        var provider = new PasskeyAuthenticationProvider(Options.Create(new PasskeyOptions()));
        var credential = CreateCredential(signCount: 0);
        credential.Metadata = " ";

        using (Assert.EnterMultipleScope())
        {
            Assert.That((await provider.AuthenticateAsync(new PasskeyAssertion("cred", 1), null)).Status, Is.EqualTo(AuthenticationResultStatus.Failed));
            Assert.That((await provider.AuthenticateAsync(new PasskeyAssertion("cred", 1), credential)).Status, Is.EqualTo(AuthenticationResultStatus.Failed));
        }
    }

    [Test]
    public async Task AuthenticateAsyncShouldRejectNullJsonMetadata()
    {
        var provider = new PasskeyAuthenticationProvider(Options.Create(new PasskeyOptions()));
        var credential = CreateCredential(signCount: 0);
        credential.Metadata = "null";

        var result = await provider.AuthenticateAsync(new PasskeyAssertion("cred", 1), credential);

        Assert.That(result.Status, Is.EqualTo(AuthenticationResultStatus.Failed));
    }

    [Test]
    public void AuthenticateAsyncShouldRejectUnsupportedAssertions()
    {
        var provider = new PasskeyAuthenticationProvider(Options.Create(new PasskeyOptions()));

        Assert.ThrowsAsync<ArgumentException>(() => provider.AuthenticateAsync(new Mock<IAuthenticationAssertion>().Object, CreateCredential(signCount: 0)));
    }

    [Test]
    public async Task FindUserAsyncShouldRespectScopedUserContext()
    {
        var provider = new PasskeyAuthenticationProvider(Options.Create(new PasskeyOptions()));
        var expectedUserId = Guid.NewGuid();
        var user = new TestUser(expectedUserId, "test@example.com");
        var repository = new Mock<IIdentityRepository>();
        repository.Setup(r => r.GetCredentialForUserAsync(expectedUserId, ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new UserCredential
            {
                Id = Guid.NewGuid(),
                UserId = expectedUserId,
                ProviderType = ProviderType.Passkey,
                ProviderName = "PASSKEY",
                ProviderKey = "cred",
                Version = "v1",
                CreatedAt = DateTimeOffset.UtcNow,
                Status = CredentialStatus.Active
            });
        repository.Setup(r => r.GetUserByIdAsync(expectedUserId, It.IsAny<CancellationToken>())).ReturnsAsync(user);

        var result = await provider.FindUserAsync(new PasskeyAssertion("cred", 1), new AuthenticationContext(UserId: expectedUserId), repository.Object);

        Assert.That(result, Is.EqualTo(user));
        repository.Verify(r => r.GetUserByProviderKeyAsync(It.IsAny<ProviderType>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task FindUserAsyncShouldUseProviderKeyWhenContextIsUnscoped()
    {
        var provider = new PasskeyAuthenticationProvider(Options.Create(new PasskeyOptions()));
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var repository = new Mock<IIdentityRepository>();
        repository.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var result = await provider.FindUserAsync(new PasskeyAssertion("cred", 1), new AuthenticationContext(), repository.Object);

        Assert.That(result, Is.EqualTo(user));
    }

    [Test]
    public async Task FindUserAsyncShouldReturnNullForUnsupportedOrMissingScopedCredential()
    {
        var provider = new PasskeyAuthenticationProvider(Options.Create(new PasskeyOptions()));
        var repository = new Mock<IIdentityRepository>();
        var userId = Guid.NewGuid();
        repository.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>()))
            .ReturnsAsync((UserCredential?)null);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(await provider.FindUserAsync(new Mock<IAuthenticationAssertion>().Object, new AuthenticationContext(), repository.Object), Is.Null);
            Assert.That(await provider.FindUserAsync(new PasskeyAssertion("cred", 1), new AuthenticationContext(UserId: userId), repository.Object), Is.Null);
        }
    }

    private static UserCredential CreateCredential(long signCount)
    {
        return new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Passkey,
            ProviderName = "PASSKEY",
            ProviderKey = "cred",
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            Metadata = JsonSerializer.Serialize(new PasskeyCredentialMetadata { DisplayName = "Laptop", PublicKey = "pk", SignCount = signCount }, PasskeyJson.Options)
        };
    }
}


