using System.Text.Json.Nodes;

namespace Ashlar.ProviderContractTests.Identity;

internal abstract class AuthenticationSessionRepositoryContractTests : ProviderContractFixture
{
    private static readonly DateTimeOffset CreatedAt = new(2026, 6, 2, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task CreateAndFetchSessionByTokenHashAndIdMapsFields()
    {
        await using var scope = CreateAsyncScope();
        var identityRepository = GetIdentityRepository(scope.ServiceProvider);
        var sessionRepository = GetAuthenticationSessionRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(identityRepository);
        var session = CreateSession(user.Id, tenantId: Guid.NewGuid());
        session.LastSeenAt = CreatedAt.AddMinutes(5);
        session.RevokedAt = CreatedAt.AddMinutes(10);
        session.RevocationReason = "signed-out";
        session.IpAddress = "203.0.113.10";
        session.UserAgent = "NUnit";
        session.Metadata = """{"device":"test"}""";
        session.AuthenticatedAt = CreatedAt.AddMinutes(1);
        session.PrimaryProvider = AuthenticationProviderKey.MagicLink;
        session.AdditionalVerificationAt = CreatedAt.AddMinutes(2);
        session.AdditionalVerificationProvider = new AuthenticationProviderKey(ProviderType.Mfa, "totp");
        session.AdditionalVerificationFactor = "totp";

        await sessionRepository.CreateSessionAsync(session);

        var fetchedByToken = await sessionRepository.GetSessionByTokenHashAsync(session.TokenHash);
        var fetchedById = await sessionRepository.GetSessionAsync(session.Id);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetchedByToken, Is.Not.Null);
            Assert.That(fetchedById, Is.Not.Null);
            Assert.That(fetchedByToken!.Id, Is.EqualTo(session.Id));
            Assert.That(fetchedByToken.UserId, Is.EqualTo(session.UserId));
            Assert.That(fetchedByToken.TenantId, Is.EqualTo(session.TenantId));
            Assert.That(fetchedByToken.TokenHash, Is.EqualTo(session.TokenHash));
            Assert.That(fetchedByToken.CreatedAt, Is.EqualTo(session.CreatedAt));
            Assert.That(fetchedByToken.AuthenticatedAt, Is.EqualTo(session.AuthenticatedAt));
            Assert.That(fetchedByToken.PrimaryProvider, Is.EqualTo(session.PrimaryProvider));
            Assert.That(fetchedByToken.AdditionalVerificationAt, Is.EqualTo(session.AdditionalVerificationAt));
            Assert.That(fetchedByToken.AdditionalVerificationProvider, Is.EqualTo(session.AdditionalVerificationProvider));
            Assert.That(fetchedByToken.AdditionalVerificationFactor, Is.EqualTo(session.AdditionalVerificationFactor));
            Assert.That(fetchedByToken.ExpiresAt, Is.EqualTo(session.ExpiresAt));
            Assert.That(fetchedByToken.LastSeenAt, Is.EqualTo(session.LastSeenAt));
            Assert.That(fetchedByToken.RevokedAt, Is.EqualTo(session.RevokedAt));
            Assert.That(fetchedByToken.RevocationReason, Is.EqualTo(session.RevocationReason));
            Assert.That(fetchedByToken.IpAddress, Is.EqualTo(session.IpAddress));
            Assert.That(fetchedByToken.UserAgent, Is.EqualTo(session.UserAgent));
            Assert.That(JsonEquals(fetchedByToken.Metadata, session.Metadata), Is.True);
            Assert.That(fetchedById!.Id, Is.EqualTo(session.Id));
            Assert.That(fetchedById.UserId, Is.EqualTo(session.UserId));
        }
    }

    [Test]
    public async Task MissingSessionReturnsNull()
    {
        await using var scope = CreateAsyncScope();
        var repository = GetAuthenticationSessionRepository(scope.ServiceProvider);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(await repository.GetSessionByTokenHashAsync("missing-token"), Is.Null);
            Assert.That(await repository.GetSessionAsync(Guid.NewGuid()), Is.Null);
        }
    }

    [Test]
    public async Task TokenHashUniquenessIsEnforced()
    {
        await using var scope = CreateAsyncScope();
        var identityRepository = GetIdentityRepository(scope.ServiceProvider);
        var repository = GetAuthenticationSessionRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(identityRepository);
        var first = CreateSession(user.Id);
        var second = CreateSession(user.Id, first.TokenHash);

        await repository.CreateSessionAsync(first);

        Assert.That(async () => await repository.CreateSessionAsync(second), Throws.Exception);
    }

    [Test]
    public async Task UpdateLastSeenOnlyMovesForwardAndRejectsRevokedAndExpiredSessions()
    {
        await using var scope = CreateAsyncScope();
        var identityRepository = GetIdentityRepository(scope.ServiceProvider);
        var repository = GetAuthenticationSessionRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(identityRepository);
        var active = CreateSession(user.Id);
        var revoked = CreateSession(user.Id);
        var expired = CreateSession(user.Id, expiresAt: CreatedAt.AddMinutes(30));
        var newer = CreatedAt.AddHours(1);
        var older = CreatedAt.AddMinutes(45);
        await repository.CreateSessionAsync(active);
        await repository.CreateSessionAsync(revoked);
        await repository.CreateSessionAsync(expired);
        await repository.RevokeSessionAsync(revoked.Id, CreatedAt.AddMinutes(20), "manual");

        var first = await repository.UpdateSessionLastSeenAsync(active.Id, newer);
        var second = await repository.UpdateSessionLastSeenAsync(active.Id, older);
        var revokedUpdate = await repository.UpdateSessionLastSeenAsync(revoked.Id, newer);
        var expiredUpdate = await repository.UpdateSessionLastSeenAsync(expired.Id, newer);
        var fetchedActive = await repository.GetSessionAsync(active.Id);
        var fetchedRevoked = await repository.GetSessionAsync(revoked.Id);
        var fetchedExpired = await repository.GetSessionAsync(expired.Id);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(first, Is.True);
            Assert.That(second, Is.False);
            Assert.That(revokedUpdate, Is.False);
            Assert.That(expiredUpdate, Is.False);
            Assert.That(fetchedActive!.LastSeenAt, Is.EqualTo(newer));
            Assert.That(fetchedRevoked!.LastSeenAt, Is.Null);
            Assert.That(fetchedExpired!.LastSeenAt, Is.Null);
        }
    }

    [Test]
    public async Task MarkStepUpVerifiedUpdatesOnlyActiveOwnedSessions()
    {
        await using var scope = CreateAsyncScope();
        var identityRepository = GetIdentityRepository(scope.ServiceProvider);
        var repository = GetAuthenticationSessionRepository(scope.ServiceProvider);
        var owner = await CreateUserAsync(identityRepository);
        var otherUser = await CreateUserAsync(identityRepository);
        var target = CreateSession(owner.Id);
        var otherOwnerSession = CreateSession(owner.Id);
        var otherUserSession = CreateSession(otherUser.Id);
        var verifiedAt = CreatedAt.AddHours(1);
        var provider = new AuthenticationProviderKey(ProviderType.Mfa, "totp");
        await repository.CreateSessionAsync(target);
        await repository.CreateSessionAsync(otherOwnerSession);
        await repository.CreateSessionAsync(otherUserSession);

        var updated = await repository.MarkStepUpVerifiedAsync(target.Id, owner.Id, verifiedAt, provider, "totp");
        var fetchedOtherOwner = await repository.GetSessionAsync(otherOwnerSession.Id);
        var fetchedOtherUser = await repository.GetSessionAsync(otherUserSession.Id);

        Assert.That(updated, Is.Not.Null);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(updated!.Id, Is.EqualTo(target.Id));
            Assert.That(updated.AdditionalVerificationAt, Is.EqualTo(verifiedAt));
            Assert.That(updated.AdditionalVerificationProvider, Is.EqualTo(provider));
            Assert.That(updated.AdditionalVerificationFactor, Is.EqualTo("totp"));
            Assert.That(fetchedOtherOwner!.AdditionalVerificationAt, Is.Null);
            Assert.That(fetchedOtherUser!.AdditionalVerificationAt, Is.Null);
        }
    }

    [Test]
    public async Task MarkStepUpVerifiedRejectsWrongUserRevokedAndExpiredSessions()
    {
        await using var scope = CreateAsyncScope();
        var identityRepository = GetIdentityRepository(scope.ServiceProvider);
        var repository = GetAuthenticationSessionRepository(scope.ServiceProvider);
        var owner = await CreateUserAsync(identityRepository);
        var other = await CreateUserAsync(identityRepository);
        var active = CreateSession(owner.Id);
        var revoked = CreateSession(owner.Id);
        var expired = CreateSession(owner.Id, expiresAt: CreatedAt.AddMinutes(30));
        var verifiedAt = CreatedAt.AddHours(1);
        await repository.CreateSessionAsync(active);
        await repository.CreateSessionAsync(revoked);
        await repository.CreateSessionAsync(expired);
        await repository.RevokeSessionAsync(revoked.Id, CreatedAt.AddMinutes(20), "manual");

        var wrongUser = await repository.MarkStepUpVerifiedAsync(active.Id, other.Id, verifiedAt, AuthenticationProviderKey.Passkey, "passkey");
        var revokedUpdate = await repository.MarkStepUpVerifiedAsync(revoked.Id, owner.Id, verifiedAt, AuthenticationProviderKey.Passkey, "passkey");
        var expiredUpdate = await repository.MarkStepUpVerifiedAsync(expired.Id, owner.Id, verifiedAt, AuthenticationProviderKey.Passkey, "passkey");
        var fetchedActive = await repository.GetSessionAsync(active.Id);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(wrongUser, Is.Null);
            Assert.That(revokedUpdate, Is.Null);
            Assert.That(expiredUpdate, Is.Null);
            Assert.That(fetchedActive!.AdditionalVerificationAt, Is.Null);
        }
    }

    [Test]
    public async Task RevocationOperationsPreserveFirstRevocationAndOwnership()
    {
        await using var scope = CreateAsyncScope();
        var identityRepository = GetIdentityRepository(scope.ServiceProvider);
        var repository = GetAuthenticationSessionRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(identityRepository);
        var otherUser = await CreateUserAsync(identityRepository);
        var single = CreateSession(user.Id);
        var alreadyRevoked = CreateSession(user.Id);
        var active = CreateSession(user.Id);
        var other = CreateSession(otherUser.Id);
        var firstRevokedAt = CreatedAt.AddHours(1);
        var secondRevokedAt = CreatedAt.AddHours(2);
        await repository.CreateSessionAsync(single);
        await repository.CreateSessionAsync(alreadyRevoked);
        await repository.CreateSessionAsync(active);
        await repository.CreateSessionAsync(other);

        var singleFirst = await repository.RevokeSessionAsync(single.Id, firstRevokedAt, "single");
        var singleSecond = await repository.RevokeSessionAsync(single.Id, secondRevokedAt, "again");
        await repository.RevokeSessionAsync(alreadyRevoked.Id, firstRevokedAt, "manual");
        var bulkCount = await repository.RevokeSessionsForUserAsync(user.Id, secondRevokedAt, "bulk");
        var wrongOwner = await repository.RevokeSessionByIdAsync(other.Id, user.Id, secondRevokedAt, "wrong");
        var rightOwner = await repository.RevokeSessionByIdAsync(other.Id, otherUser.Id, secondRevokedAt, "right");
        var fetchedSingle = await repository.GetSessionAsync(single.Id);
        var fetchedAlreadyRevoked = await repository.GetSessionAsync(alreadyRevoked.Id);
        var fetchedActive = await repository.GetSessionAsync(active.Id);
        var fetchedOther = await repository.GetSessionAsync(other.Id);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(singleFirst, Is.True);
            Assert.That(singleSecond, Is.False);
            Assert.That(bulkCount, Is.EqualTo(1));
            Assert.That(wrongOwner, Is.False);
            Assert.That(rightOwner, Is.True);
            Assert.That(fetchedSingle!.RevokedAt, Is.EqualTo(firstRevokedAt));
            Assert.That(fetchedSingle.RevocationReason, Is.EqualTo("single"));
            Assert.That(fetchedAlreadyRevoked!.RevokedAt, Is.EqualTo(firstRevokedAt));
            Assert.That(fetchedAlreadyRevoked.RevocationReason, Is.EqualTo("manual"));
            Assert.That(fetchedActive!.RevokedAt, Is.EqualTo(secondRevokedAt));
            Assert.That(fetchedActive.RevocationReason, Is.EqualTo("bulk"));
            Assert.That(fetchedOther!.RevokedAt, Is.EqualTo(secondRevokedAt));
            Assert.That(fetchedOther.RevocationReason, Is.EqualTo("right"));
        }
    }

    [Test]
    public async Task ListSessionsSupportsActiveOnlyFiltering()
    {
        await using var scope = CreateAsyncScope();
        var identityRepository = GetIdentityRepository(scope.ServiceProvider);
        var repository = GetAuthenticationSessionRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(identityRepository);
        var active = CreateSession(user.Id);
        var revoked = CreateSession(user.Id);
        var expired = CreateSession(user.Id, expiresAt: CreatedAt.AddMinutes(30));
        await repository.CreateSessionAsync(active);
        await repository.CreateSessionAsync(revoked);
        await repository.CreateSessionAsync(expired);
        await repository.RevokeSessionAsync(revoked.Id, CreatedAt.AddMinutes(10), "test");

        var activeOnly = await repository.ListSessionsForUserAsync(user.Id, activeOnly: true, CreatedAt.AddHours(1));
        var all = await repository.ListSessionsForUserAsync(user.Id, activeOnly: false, CreatedAt.AddHours(1));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(activeOnly.Select(session => session.Id), Is.EquivalentTo(new[] { active.Id }));
            Assert.That(all.Select(session => session.Id), Is.EquivalentTo(new[] { active.Id, revoked.Id, expired.Id }));
        }
    }

    [Test]
    public async Task RevokeOtherSessionsPreservesExcludedSession()
    {
        await using var scope = CreateAsyncScope();
        var identityRepository = GetIdentityRepository(scope.ServiceProvider);
        var repository = GetAuthenticationSessionRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(identityRepository);
        var current = CreateSession(user.Id);
        var other1 = CreateSession(user.Id);
        var other2 = CreateSession(user.Id);
        var revokedAt = CreatedAt.AddHours(1);
        await repository.CreateSessionAsync(current);
        await repository.CreateSessionAsync(other1);
        await repository.CreateSessionAsync(other2);

        var count = await repository.RevokeOtherSessionsForUserAsync(user.Id, current.Id, revokedAt, "security-sweep");
        var fetchedCurrent = await repository.GetSessionAsync(current.Id);
        var fetchedOther1 = await repository.GetSessionAsync(other1.Id);
        var fetchedOther2 = await repository.GetSessionAsync(other2.Id);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(count, Is.EqualTo(2));
            Assert.That(fetchedCurrent!.RevokedAt, Is.Null);
            Assert.That(fetchedOther1!.RevokedAt, Is.EqualTo(revokedAt));
            Assert.That(fetchedOther2!.RevokedAt, Is.EqualTo(revokedAt));
        }
    }

    [Test]
    public async Task SessionWritesRollBackWhenProviderSupportsTransactions()
    {
        Guid sessionId;
        await using (var scope = CreateAsyncScope())
        {
            var transactionProvider = GetTransactionProvider(scope.ServiceProvider);
            if (transactionProvider == null)
            {
                Assert.Ignore("Provider does not register IAshlarTransactionProvider.");
            }

            var identityRepository = GetIdentityRepository(scope.ServiceProvider);
            var repository = GetAuthenticationSessionRepository(scope.ServiceProvider);
            var user = await CreateUserAsync(identityRepository);
            var session = CreateSession(user.Id);
            sessionId = session.Id;

            await using var transaction = await transactionProvider.BeginTransactionAsync();
            await repository.CreateSessionAsync(session);
            await transaction.RollbackAsync();
        }

        await using var verificationScope = CreateAsyncScope();
        var verificationRepository = GetAuthenticationSessionRepository(verificationScope.ServiceProvider);
        Assert.That(await verificationRepository.GetSessionAsync(sessionId), Is.Null);
    }

    private static AuthenticationSession CreateSession(
        Guid userId,
        string? tokenHash = null,
        DateTimeOffset? expiresAt = null,
        Guid? tenantId = null)
    {
        return new AuthenticationSession
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            TenantId = tenantId,
            TokenHash = tokenHash ?? $"sha256:{Guid.NewGuid():N}",
            CreatedAt = CreatedAt,
            ExpiresAt = expiresAt ?? CreatedAt.AddDays(1)
        };
    }

    private static bool JsonEquals(string? left, string? right)
    {
        if (left == null || right == null)
        {
            return left == right;
        }

        return JsonNode.DeepEquals(JsonNode.Parse(left), JsonNode.Parse(right));
    }
}


