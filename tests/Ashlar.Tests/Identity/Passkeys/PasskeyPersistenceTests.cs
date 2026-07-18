using Ashlar.Identity.Models.Passkeys;
using Ashlar.Identity.Passkeys;
using Ashlar.Passkeys;
using Microsoft.Extensions.Options;
using Moq;

namespace Ashlar.Tests.Identity.Passkeys;

internal sealed class PasskeyPersistenceTests
{
    [Test]
    public async Task CredentialLookupChecksPasskeyRegistration()
    {
        var user = Mock.Of<IUser>();
        var users = new Mock<IUserRepository>();
        users.SetupSequence(x => x.GetUserByProviderKeyAsync(ProviderType.Passkey, "passkey", "key", It.IsAny<CancellationToken>()))
            .ReturnsAsync(user)
            .ReturnsAsync((IUser?)null);
        var lookup = new PasskeyCredentialStore(users.Object, Mock.Of<ICredentialRepository>(), Options.Create(new PasskeyOptions { ProviderName = "passkey" }));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(await lookup.IsCredentialRegisteredAsync("key"), Is.True);
            Assert.That(await lookup.IsCredentialRegisteredAsync("key"), Is.False);
        }
    }

    [Test]
    public async Task CredentialStoreUsesCanonicalProviderName()
    {
        var users = new Mock<IUserRepository>();
        users.Setup(x => x.GetUserByProviderKeyAsync(ProviderType.Passkey, "custom-passkey", "key", It.IsAny<CancellationToken>()))
            .ReturnsAsync(Mock.Of<IUser>());
        var store = new PasskeyCredentialStore(
            users.Object,
            Mock.Of<ICredentialRepository>(),
            Options.Create(new PasskeyOptions { ProviderName = " custom-passkey " }));

        Assert.That(await store.IsCredentialRegisteredAsync("key"), Is.True);
    }

    [Test]
    public async Task CredentialStoreForwardsPasskeySpecificOperations()
    {
        var userId = Guid.NewGuid();
        var user = Mock.Of<IUser>();
        var credential = Credential(userId, ProviderType.Passkey, "passkey", "key");
        var users = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        users.Setup(x => x.GetUserByIdAsync(userId, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        users.Setup(x => x.GetUserByProviderKeyAsync(ProviderType.Passkey, "passkey", "key", It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.Setup(x => x.ListCredentialsForUserAsync(userId, true, It.IsAny<CancellationToken>())).ReturnsAsync([credential, Credential(userId, ProviderType.Local, "local", "other")]);
        credentials.Setup(x => x.GetCredentialForUserAsync(userId, ProviderType.Passkey, "passkey", "key", It.IsAny<CancellationToken>())).ReturnsAsync(credential);
        credentials.Setup(x => x.UpdateCredentialAsync(credential, "v1", It.IsAny<CancellationToken>())).ReturnsAsync(true);
        var store = new PasskeyCredentialStore(users.Object, credentials.Object, Options.Create(new PasskeyOptions { ProviderName = "passkey" }));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(await store.GetUserByIdAsync(userId), Is.SameAs(user));
            Assert.That(await store.GetUserByPasskeyAsync("key"), Is.SameAs(user));
            Assert.That(await store.ListPasskeysAsync(userId), Is.EqualTo(new[] { credential }));
            Assert.That(await store.GetPasskeyAsync(userId, "key"), Is.SameAs(credential));
            Assert.That(await store.UpdatePasskeyAsync(credential, "v1"), Is.True);
        }
        await store.CreatePasskeyAsync(credential);
        credentials.Verify(x => x.CreateOrReplaceCredentialAsync(credential, It.IsAny<CancellationToken>()));
    }

    [Test]
    public async Task ChallengeStoreForwardsChallengeOperations()
    {
        var challenge = new PasskeyChallenge { Id = Guid.NewGuid(), Version = "v1", Purpose = "test", Challenge = "challenge", OptionsJson = "{}", RelyingPartyId = "example.com", Origin = "https://example.com", CreatedAt = DateTimeOffset.UtcNow, ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(1) };
        var challenges = new Mock<IPasskeyChallengeRepository>();
        challenges.Setup(x => x.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(x => x.ConsumeAsync(challenge.Id, "v1", It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(true);
        var store = new PasskeyChallengeStore(challenges.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(await store.GetAsync(challenge.Id), Is.SameAs(challenge));
            Assert.That(await store.ConsumeAsync(challenge.Id, "v1", DateTimeOffset.UtcNow), Is.True);
        }
        await store.CreateAsync(challenge);
        challenges.Verify(x => x.CreateAsync(challenge, It.IsAny<CancellationToken>()));
    }

    private static UserCredential Credential(Guid userId, ProviderType type, string name, string key) => new()
    {
        Id = Guid.NewGuid(),
        UserId = userId,
        ProviderType = type,
        ProviderName = name,
        ProviderKey = key,
        Version = "v1",
        CreatedAt = DateTimeOffset.UtcNow,
        Status = CredentialStatus.Active
    };
}
