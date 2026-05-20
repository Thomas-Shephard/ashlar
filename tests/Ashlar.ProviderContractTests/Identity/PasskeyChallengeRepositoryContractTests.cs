using Ashlar.Identity.Models.Passkeys;
using System.Text.Json.Nodes;

namespace Ashlar.ProviderContractTests.Identity;

internal abstract class PasskeyChallengeRepositoryContractTests : ProviderContractFixture
{
    private static readonly TimeSpan ChallengeLifetime = TimeSpan.FromMinutes(5);

    [Test]
    public async Task CreateAndFetchChallengeByIdMapsCoreFields()
    {
        await using var scope = CreateAsyncScope();
        var identityRepository = GetIdentityRepository(scope.ServiceProvider);
        var repository = GetPasskeyChallengeRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(identityRepository);
        var challenge = CreateAuthenticationChallenge(user.Id);

        await repository.CreateAsync(challenge);

        var fetched = await repository.GetAsync(challenge.Id);

        Assert.That(fetched, Is.Not.Null);
        AssertChallenge(fetched!, challenge);
    }

    [Test]
    public async Task FetchMissingChallengeReturnsNull()
    {
        await using var scope = CreateAsyncScope();
        var repository = GetPasskeyChallengeRepository(scope.ServiceProvider);

        Assert.That(await repository.GetAsync(Guid.NewGuid()), Is.Null);
    }

    [Test]
    public async Task RegistrationChallengeRoundTrips()
    {
        await using var scope = CreateAsyncScope();
        var identityRepository = GetIdentityRepository(scope.ServiceProvider);
        var repository = GetPasskeyChallengeRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(identityRepository);
        var challenge = CreateRegistrationChallenge(user.Id);

        await repository.CreateAsync(challenge);

        var fetched = await repository.GetAsync(challenge.Id);

        AssertChallenge(fetched!, challenge);
    }

    [Test]
    public async Task AuthenticationChallengeWithHandshakeBindingRoundTrips()
    {
        await using var scope = CreateAsyncScope();
        var identityRepository = GetIdentityRepository(scope.ServiceProvider);
        var repository = GetPasskeyChallengeRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(identityRepository);
        var challenge = CreateAuthenticationChallenge(user.Id, handshakeTokenHash: "hash:handshake", factorType: "passkey");

        await repository.CreateAsync(challenge);

        var fetched = await repository.GetAsync(challenge.Id);

        using (Assert.EnterMultipleScope())
        {
            AssertChallenge(fetched!, challenge);
            Assert.That(fetched!.HandshakeTokenHash, Is.EqualTo("hash:handshake"));
            Assert.That(fetched.FactorType, Is.EqualTo("passkey"));
        }
    }

    [Test]
    public async Task ChallengeValueUniquenessIsEnforced()
    {
        await using var scope = CreateAsyncScope();
        var identityRepository = GetIdentityRepository(scope.ServiceProvider);
        var repository = GetPasskeyChallengeRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(identityRepository);
        var first = CreateAuthenticationChallenge(user.Id);
        var duplicate = CreateAuthenticationChallenge(user.Id, challengeValue: first.Challenge);
        await repository.CreateAsync(first);

        Assert.That(async () => await repository.CreateAsync(duplicate), Throws.Exception);
    }

    [Test]
    public async Task ConsumeAsyncSucceedsOnceWithCorrectVersion()
    {
        await using var scope = CreateAsyncScope();
        var identityRepository = GetIdentityRepository(scope.ServiceProvider);
        var repository = GetPasskeyChallengeRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(identityRepository);
        var challenge = CreateAuthenticationChallenge(user.Id);
        await repository.CreateAsync(challenge);

        var consumedAt = DateTimeOffset.UtcNow;
        var consumed = await repository.ConsumeAsync(challenge.Id, challenge.Version, consumedAt);
        var replayed = await repository.ConsumeAsync(challenge.Id, challenge.Version, consumedAt.AddMinutes(1));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(consumed, Is.True);
            Assert.That(replayed, Is.False);
        }
    }

    [Test]
    public async Task ConsumeAsyncRejectsStaleOrWrongVersion()
    {
        await using var scope = CreateAsyncScope();
        var identityRepository = GetIdentityRepository(scope.ServiceProvider);
        var repository = GetPasskeyChallengeRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(identityRepository);
        var challenge = CreateAuthenticationChallenge(user.Id);
        await repository.CreateAsync(challenge);

        var consumed = await repository.ConsumeAsync(challenge.Id, "wrong-version", DateTimeOffset.UtcNow);

        Assert.That(consumed, Is.False);
    }

    [Test]
    public async Task ConsumeAsyncRejectsAlreadyConsumedChallenge()
    {
        await using var scope = CreateAsyncScope();
        var identityRepository = GetIdentityRepository(scope.ServiceProvider);
        var repository = GetPasskeyChallengeRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(identityRepository);
        var challenge = CreateAuthenticationChallenge(user.Id);
        await repository.CreateAsync(challenge);
        await repository.ConsumeAsync(challenge.Id, challenge.Version, DateTimeOffset.UtcNow);
        var consumedChallenge = await repository.GetAsync(challenge.Id);

        var consumedAgain = await repository.ConsumeAsync(challenge.Id, consumedChallenge!.Version, DateTimeOffset.UtcNow.AddMinutes(1));

        Assert.That(consumedAgain, Is.False);
    }

    [Test]
    public async Task ConsumeAsyncRejectsExpiredChallenge()
    {
        await using var scope = CreateAsyncScope();
        var identityRepository = GetIdentityRepository(scope.ServiceProvider);
        var repository = GetPasskeyChallengeRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(identityRepository);
        var now = DateTimeOffset.UtcNow;
        var challenge = CreateAuthenticationChallenge(user.Id, createdAt: now.AddMinutes(-10), expiresAt: now.AddMinutes(-1));
        await repository.CreateAsync(challenge);

        var consumed = await repository.ConsumeAsync(challenge.Id, challenge.Version, now);

        Assert.That(consumed, Is.False);
    }

    [Test]
    public async Task SuccessfulConsumePersistsConsumedAt()
    {
        await using var scope = CreateAsyncScope();
        var identityRepository = GetIdentityRepository(scope.ServiceProvider);
        var repository = GetPasskeyChallengeRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(identityRepository);
        var challenge = CreateAuthenticationChallenge(user.Id);
        var consumedAt = DateTimeOffset.UtcNow;
        await repository.CreateAsync(challenge);

        await repository.ConsumeAsync(challenge.Id, challenge.Version, consumedAt);

        var fetched = await repository.GetAsync(challenge.Id);
        Assert.That(fetched!.ConsumedAt, Is.Not.Null);
    }

    [Test]
    public async Task PasskeyChallengeWritesRollBackWhenProviderSupportsTransactions()
    {
        Guid challengeId;
        await using (var scope = CreateAsyncScope())
        {
            var transactionProvider = GetTransactionProvider(scope.ServiceProvider);
            if (transactionProvider == null)
            {
                Assert.Ignore("Provider does not register IAshlarTransactionProvider.");
            }

            var identityRepository = GetIdentityRepository(scope.ServiceProvider);
            var repository = GetPasskeyChallengeRepository(scope.ServiceProvider);
            var user = await CreateUserAsync(identityRepository);
            var challenge = CreateAuthenticationChallenge(user.Id);
            challengeId = challenge.Id;

            await using var transaction = await transactionProvider.BeginTransactionAsync();
            await repository.CreateAsync(challenge);
            await transaction.RollbackAsync();
        }

        await using var verificationScope = CreateAsyncScope();
        var verificationRepository = GetPasskeyChallengeRepository(verificationScope.ServiceProvider);
        Assert.That(await verificationRepository.GetAsync(challengeId), Is.Null);
    }

    private static PasskeyChallenge CreateRegistrationChallenge(Guid userId)
    {
        return CreateChallenge(
            "passkey-registration",
            userId,
            handshakeTokenHash: null,
            factorType: null,
            displayName: "Work Laptop",
            optionsJson: """{"challenge":"registration","user":{"name":"user@example.com","displayName":"Test User"},"rp":{"id":"example.com","name":"Example"}}""");
    }

    private static PasskeyChallenge CreateAuthenticationChallenge(
        Guid userId,
        string? handshakeTokenHash = "hash:step-up",
        string? factorType = "passkey",
        DateTimeOffset? createdAt = null,
        DateTimeOffset? expiresAt = null,
        string? challengeValue = null)
    {
        return CreateChallenge(
            "passkey-authentication",
            userId,
            handshakeTokenHash,
            factorType,
            displayName: null,
            optionsJson: """{"challenge":"authentication","allowCredentials":[]}""",
            createdAt: createdAt,
            expiresAt: expiresAt,
            challengeValue: challengeValue);
    }

    private static PasskeyChallenge CreateChallenge(
        string purpose,
        Guid userId,
        string? handshakeTokenHash,
        string? factorType,
        string? displayName,
        string optionsJson,
        DateTimeOffset? createdAt = null,
        DateTimeOffset? expiresAt = null,
        string? challengeValue = null)
    {
        var now = createdAt ?? DateTimeOffset.UtcNow;
        return new PasskeyChallenge
        {
            Id = Guid.NewGuid(),
            Version = Guid.NewGuid().ToString("N"),
            Purpose = purpose,
            UserId = userId,
            HandshakeTokenHash = handshakeTokenHash,
            FactorType = factorType,
            DisplayName = displayName,
            Challenge = challengeValue ?? Guid.NewGuid().ToString("N"),
            OptionsJson = optionsJson,
            RelyingPartyId = "example.com",
            Origin = "https://example.com",
            CreatedAt = now,
            ExpiresAt = expiresAt ?? now.Add(ChallengeLifetime)
        };
    }

    private static void AssertChallenge(PasskeyChallenge actual, PasskeyChallenge expected)
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(actual.Id, Is.EqualTo(expected.Id));
            Assert.That(actual.Version, Is.EqualTo(expected.Version));
            Assert.That(actual.Purpose, Is.EqualTo(expected.Purpose));
            Assert.That(actual.UserId, Is.EqualTo(expected.UserId));
            Assert.That(actual.HandshakeTokenHash, Is.EqualTo(expected.HandshakeTokenHash));
            Assert.That(actual.FactorType, Is.EqualTo(expected.FactorType));
            Assert.That(actual.DisplayName, Is.EqualTo(expected.DisplayName));
            Assert.That(actual.Challenge, Is.EqualTo(expected.Challenge));
            Assert.That(JsonNode.DeepEquals(JsonNode.Parse(actual.OptionsJson), JsonNode.Parse(expected.OptionsJson)), Is.True);
            Assert.That(actual.RelyingPartyId, Is.EqualTo(expected.RelyingPartyId));
            Assert.That(actual.Origin, Is.EqualTo(expected.Origin));
            Assert.That(actual.CreatedAt, Is.EqualTo(expected.CreatedAt).Within(TimeSpan.FromMilliseconds(1)));
            Assert.That(actual.ExpiresAt, Is.EqualTo(expected.ExpiresAt).Within(TimeSpan.FromMilliseconds(1)));
            Assert.That(actual.ConsumedAt, Is.EqualTo(expected.ConsumedAt));
        }
    }
}
