using System.Text.Json.Nodes;

namespace Ashlar.ProviderContractTests.Identity;

/// <summary>Tests session persistence, tenant isolation, lifecycle transitions, revocation, and rollback.</summary>
public abstract class AuthenticationSessionRepositoryContractTests : ProviderContractFixture
{
    private static readonly DateTimeOffset CreatedAt = new(2026, 6, 2, 12, 0, 0, TimeSpan.Zero);

    /// <summary>Verifies that both session keys recover the same complete stored session.</summary>
    [Test]
    public async Task CreateAndFetchSessionByTokenHashAndIdMapsFields()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var sessionRepository = GetAuthenticationSessionRepository(scope.ServiceProvider);
        var tenantId = Guid.NewGuid();
        var user = await CreateUserAsync(userRepository, tenantId: tenantId);
        var session = CreateSession(user.Id, tenantId: tenantId);
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

    /// <summary>Leaves unknown session identifiers distinguishable from stored sessions.</summary>
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

    /// <summary>Verifies that a token hash cannot identify more than one session.</summary>
    [Test]
    public async Task TokenHashUniquenessIsEnforced()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var repository = GetAuthenticationSessionRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(userRepository);
        var first = CreateSession(user.Id);
        var second = CreateSession(user.Id, first.TokenHash);

        await repository.CreateSessionAsync(first);

        Assert.That(async () => await repository.CreateSessionAsync(second), Throws.Exception);
    }

    /// <summary>Verifies that a session cannot assign a tenant user to another tenant.</summary>
    [Test]
    public async Task CreateSessionRejectsTenantUserWithDifferentTenant()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var repository = GetAuthenticationSessionRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(userRepository, tenantId: Guid.NewGuid());

        Assert.That(async () => await repository.CreateSessionAsync(CreateSession(user.Id, tenantId: Guid.NewGuid())), Throws.Exception);
    }

    /// <summary>Verifies that a tenant user cannot receive a global session.</summary>
    [Test]
    public async Task CreateSessionRejectsTenantUserWithNullTenant()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var repository = GetAuthenticationSessionRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(userRepository, tenantId: Guid.NewGuid());

        Assert.That(async () => await repository.CreateSessionAsync(CreateSession(user.Id, tenantId: null)), Throws.Exception);
    }

    /// <summary>Verifies that a global user cannot receive a tenant session.</summary>
    [Test]
    public async Task CreateSessionRejectsGlobalUserWithTenant()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var repository = GetAuthenticationSessionRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(userRepository);

        Assert.That(async () => await repository.CreateSessionAsync(CreateSession(user.Id, tenantId: Guid.NewGuid())), Throws.Exception);
    }

    /// <summary>Verifies that valid tenant and global sessions remain independently retrievable.</summary>
    [Test]
    public async Task CreateSessionPersistsMatchingTenantAndGlobalRows()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var repository = GetAuthenticationSessionRepository(scope.ServiceProvider);
        var tenantId = Guid.NewGuid();
        var tenantUser = await CreateUserAsync(userRepository, tenantId: tenantId);
        var globalUser = await CreateUserAsync(userRepository);
        var tenantSession = CreateSession(tenantUser.Id, tenantId: tenantId);
        var globalSession = CreateSession(globalUser.Id);

        await repository.CreateSessionAsync(tenantSession);
        await repository.CreateSessionAsync(globalSession);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(await repository.GetSessionAsync(tenantSession.Id), Is.Not.Null);
            Assert.That(await repository.GetSessionAsync(globalSession.Id), Is.Not.Null);
        }
    }

    /// <summary>Verifies that last-seen time moves only forward on active sessions.</summary>
    [Test]
    public async Task UpdateLastSeenOnlyMovesForwardAndRejectsRevokedAndExpiredSessions()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var repository = GetAuthenticationSessionRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(userRepository);
        var active = CreateSession(user.Id);
        var revoked = CreateSession(user.Id);
        var expired = CreateSession(user.Id, expiresAt: CreatedAt.AddMinutes(30));
        var newer = CreatedAt.AddHours(1);
        var older = CreatedAt.AddMinutes(45);
        await repository.CreateSessionAsync(active);
        await repository.CreateSessionAsync(revoked);
        await repository.CreateSessionAsync(expired);
        await repository.RevokeSessionByIdAsync(revoked.Id, revoked.UserId, CreatedAt.AddMinutes(20), "manual", tenant: null, includeAllTenants: true);

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

    /// <summary>Verifies that step-up verification updates only an active session owned by the user.</summary>
    [Test]
    public async Task MarkStepUpVerifiedUpdatesOnlyActiveOwnedSessions()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var repository = GetAuthenticationSessionRepository(scope.ServiceProvider);
        var owner = await CreateUserAsync(userRepository);
        var otherUser = await CreateUserAsync(userRepository);
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

    /// <summary>Verifies that another user or a terminal session cannot receive step-up verification.</summary>
    [Test]
    public async Task MarkStepUpVerifiedRejectsWrongUserRevokedAndExpiredSessions()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var repository = GetAuthenticationSessionRepository(scope.ServiceProvider);
        var owner = await CreateUserAsync(userRepository);
        var other = await CreateUserAsync(userRepository);
        var active = CreateSession(owner.Id);
        var revoked = CreateSession(owner.Id);
        var expired = CreateSession(owner.Id, expiresAt: CreatedAt.AddMinutes(30));
        var verifiedAt = CreatedAt.AddHours(1);
        await repository.CreateSessionAsync(active);
        await repository.CreateSessionAsync(revoked);
        await repository.CreateSessionAsync(expired);
        await repository.RevokeSessionByIdAsync(revoked.Id, revoked.UserId, CreatedAt.AddMinutes(20), "manual", tenant: null, includeAllTenants: true);

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

    /// <summary>Preserves the original revocation details and refuses revocation by another user.</summary>
    [Test]
    public async Task RevocationOperationsPreserveFirstRevocationAndOwnership()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var repository = GetAuthenticationSessionRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(userRepository);
        var otherUser = await CreateUserAsync(userRepository);
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

        var singleFirst = await repository.RevokeSessionByIdAsync(single.Id, single.UserId, firstRevokedAt, "single", tenant: null, includeAllTenants: true);
        var singleSecond = await repository.RevokeSessionByIdAsync(single.Id, single.UserId, secondRevokedAt, "again", tenant: null, includeAllTenants: true);
        await repository.RevokeSessionByIdAsync(alreadyRevoked.Id, alreadyRevoked.UserId, firstRevokedAt, "manual", tenant: null, includeAllTenants: true);
        var bulkCount = await repository.RevokeSessionsForUserAsync(user.Id, secondRevokedAt, "bulk", tenant: null, includeAllTenants: true);
        var wrongOwner = await repository.RevokeSessionByIdAsync(other.Id, user.Id, secondRevokedAt, "wrong", tenant: null, includeAllTenants: true);
        var rightOwner = await repository.RevokeSessionByIdAsync(other.Id, otherUser.Id, secondRevokedAt, "right", tenant: null, includeAllTenants: true);
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

    /// <summary>Verifies that active-only listing excludes revoked and expired sessions.</summary>
    [Test]
    public async Task ListSessionsSupportsActiveOnlyFiltering()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var repository = GetAuthenticationSessionRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(userRepository);
        var active = CreateSession(user.Id);
        var revoked = CreateSession(user.Id);
        var expired = CreateSession(user.Id, expiresAt: CreatedAt.AddMinutes(30));
        await repository.CreateSessionAsync(active);
        await repository.CreateSessionAsync(revoked);
        await repository.CreateSessionAsync(expired);
        await repository.RevokeSessionByIdAsync(revoked.Id, revoked.UserId, CreatedAt.AddMinutes(10), "test", tenant: null, includeAllTenants: true);

        var activeOnly = await repository.ListSessionsForUserAsync(user.Id, activeOnly: true, CreatedAt.AddHours(1));
        var all = await repository.ListSessionsForUserAsync(user.Id, activeOnly: false, CreatedAt.AddHours(1));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(activeOnly.Select(session => session.Id), Is.EquivalentTo(new[] { active.Id }));
            Assert.That(all.Select(session => session.Id), Is.EquivalentTo(new[] { active.Id, revoked.Id, expired.Id }));
        }
    }

    /// <summary>Verifies that bulk revocation preserves the explicitly excluded session.</summary>
    [Test]
    public async Task RevokeOtherSessionsPreservesExcludedSession()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var repository = GetAuthenticationSessionRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(userRepository);
        var current = CreateSession(user.Id);
        var other1 = CreateSession(user.Id);
        var other2 = CreateSession(user.Id);
        var revokedAt = CreatedAt.AddHours(1);
        await repository.CreateSessionAsync(current);
        await repository.CreateSessionAsync(other1);
        await repository.CreateSessionAsync(other2);

        var count = await repository.RevokeOtherSessionsForUserAsync(user.Id, current.Id, revokedAt, "security-sweep", tenant: null, includeAllTenants: true);
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

    /// <summary>Rejects bulk revocation unless its tenant reach is stated explicitly.</summary>
    [Test]
    public async Task BulkRevocationRequiresExplicitScope()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var repository = GetAuthenticationSessionRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(userRepository);

        Assert.ThrowsAsync<ArgumentException>(() =>
            repository.RevokeSessionsForUserAsync(user.Id, CreatedAt, "ambiguous", tenant: null, includeAllTenants: false));
        Assert.ThrowsAsync<ArgumentException>(() =>
            repository.RevokeSessionsForUserAsync(user.Id, CreatedAt, "conflicting", TenantContext.Global, includeAllTenants: true));
        Assert.ThrowsAsync<ArgumentException>(() =>
            repository.RevokeSessionByIdAsync(Guid.NewGuid(), user.Id, CreatedAt, "ambiguous", tenant: null, includeAllTenants: false));
        Assert.ThrowsAsync<ArgumentException>(() =>
            repository.RevokeOtherSessionsForUserAsync(user.Id, Guid.NewGuid(), CreatedAt, "ambiguous", tenant: null, includeAllTenants: false));
    }

    /// <summary>Prevents tenant-scoped revocation from changing sessions in another scope.</summary>
    [Test]
    public async Task RevocationOperationsHonorTenantScope()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var repository = GetAuthenticationSessionRepository(scope.ServiceProvider);
        var tenantA = Guid.NewGuid();
        var tenantB = Guid.NewGuid();
        var bulkUser = await CreateUserAsync(userRepository, tenantId: tenantA);
        var singleUser = await CreateUserAsync(userRepository, tenantId: tenantB);
        var otherSessionsUser = await CreateUserAsync(userRepository, tenantId: tenantA);
        var globalUser = await CreateUserAsync(userRepository);
        var tenantASession = CreateSession(bulkUser.Id, tenantId: tenantA);
        var otherTenantUser = await CreateUserAsync(userRepository, tenantId: tenantB);
        var tenantBSession = CreateSession(otherTenantUser.Id, tenantId: tenantB);
        var singleTenantB = CreateSession(singleUser.Id, tenantId: tenantB);
        var currentTenantA = CreateSession(otherSessionsUser.Id, tenantId: tenantA);
        var otherTenantA = CreateSession(otherSessionsUser.Id, tenantId: tenantA);
        var globalOnly = CreateSession(globalUser.Id);
        var firstRevokedAt = CreatedAt.AddHours(1);
        var secondRevokedAt = CreatedAt.AddHours(2);
        var thirdRevokedAt = CreatedAt.AddHours(3);
        var fourthRevokedAt = CreatedAt.AddHours(4);
        await repository.CreateSessionAsync(tenantASession);
        await repository.CreateSessionAsync(tenantBSession);
        await repository.CreateSessionAsync(singleTenantB);
        await repository.CreateSessionAsync(currentTenantA);
        await repository.CreateSessionAsync(otherTenantA);
        await repository.CreateSessionAsync(globalOnly);

        var tenantACount = await repository.RevokeSessionsForUserAsync(bulkUser.Id, firstRevokedAt, "tenant-a", new TenantContext(tenantA), includeAllTenants: false);
        var wrongTenantSingle = await repository.RevokeSessionByIdAsync(singleTenantB.Id, singleUser.Id, secondRevokedAt, "wrong-tenant", new TenantContext(tenantA), includeAllTenants: false);
        var tenantBSingle = await repository.RevokeSessionByIdAsync(singleTenantB.Id, singleUser.Id, secondRevokedAt, "tenant-b", new TenantContext(tenantB), includeAllTenants: false);
        var otherTenantACount = await repository.RevokeOtherSessionsForUserAsync(otherSessionsUser.Id, currentTenantA.Id, thirdRevokedAt, "other-tenant-a", new TenantContext(tenantA), includeAllTenants: false);
        var globalCount = await repository.RevokeSessionsForUserAsync(globalUser.Id, fourthRevokedAt, "global", TenantContext.Global, includeAllTenants: false);
        var fetchedTenantA = await repository.GetSessionAsync(tenantASession.Id);
        var fetchedTenantB = await repository.GetSessionAsync(tenantBSession.Id);
        var fetchedSingleTenantB = await repository.GetSessionAsync(singleTenantB.Id);
        var fetchedCurrentTenantA = await repository.GetSessionAsync(currentTenantA.Id);
        var fetchedOtherTenantA = await repository.GetSessionAsync(otherTenantA.Id);
        var fetchedGlobalOnly = await repository.GetSessionAsync(globalOnly.Id);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(tenantACount, Is.EqualTo(1));
            Assert.That(wrongTenantSingle, Is.False);
            Assert.That(tenantBSingle, Is.True);
            Assert.That(otherTenantACount, Is.EqualTo(1));
            Assert.That(globalCount, Is.EqualTo(1));
            Assert.That(fetchedTenantA!.RevokedAt, Is.EqualTo(firstRevokedAt));
            Assert.That(fetchedTenantB!.RevokedAt, Is.Null);
            Assert.That(fetchedSingleTenantB!.RevokedAt, Is.EqualTo(secondRevokedAt));
            Assert.That(fetchedCurrentTenantA!.RevokedAt, Is.Null);
            Assert.That(fetchedOtherTenantA!.RevokedAt, Is.EqualTo(thirdRevokedAt));
            Assert.That(fetchedGlobalOnly!.RevokedAt, Is.EqualTo(fourthRevokedAt));
        }
    }

    /// <summary>Leaves no persisted session after its surrounding transaction is rolled back.</summary>
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

            var userRepository = GetUserRepository(scope.ServiceProvider);
            var repository = GetAuthenticationSessionRepository(scope.ServiceProvider);
            var user = await CreateUserAsync(userRepository);
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
