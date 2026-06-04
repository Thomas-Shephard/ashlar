using Ashlar.Postgres.Models;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using System.Text.Json.Nodes;

namespace Ashlar.Postgres.Tests.Identity;

internal sealed class PostgresAuthenticationSessionRepositoryTests : PostgresTestBase
{
    private IServiceProvider _serviceProvider;

    public override async Task OneTimeSetUp()
    {
        await base.OneTimeSetUp();

        var services = new ServiceCollection();
        services.AddAshlarPostgres(GetConnectionString());
        _serviceProvider = services.BuildServiceProvider();

        await _serviceProvider.InitializeAshlarPostgresSchemaAsync();
    }

    [OneTimeTearDown]
    public async Task OneTimeTearDownAsync()
    {
        if (_serviceProvider is IAsyncDisposable asyncDisposable)
        {
            await asyncDisposable.DisposeAsync();
        }
        else if (_serviceProvider is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }

    [Test]
    public void ConstructorNullDataSourceShouldThrow()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new PostgresAuthenticationSessionRepository(null!));
    }

    [Test]
    public async Task CreateAndFetchSessionByTokenHashShouldMapAllFields()
    {
        var userRepository = GetUserRepository();
        var sessionRepository = GetSessionRepository();
        var tenantId = Guid.NewGuid();
        var user = await CreateTestUser(userRepository, tenantId);
        var session = CreateSession(user.Id, tenantId: tenantId);
        session.LastSeenAt = new DateTimeOffset(2026, 1, 2, 12, 5, 0, TimeSpan.Zero);
        session.RevokedAt = new DateTimeOffset(2026, 1, 2, 12, 10, 0, TimeSpan.Zero);
        session.RevocationReason = "signed-out";
        session.IpAddress = "203.0.113.10";
        session.UserAgent = "NUnit";
        session.Metadata = """{"device":"test"}""";
        session.AuthenticatedAt = new DateTimeOffset(2026, 1, 2, 12, 1, 0, TimeSpan.Zero);
        session.PrimaryProvider = AuthenticationProviderKey.MagicLink;
        session.AdditionalVerificationAt = new DateTimeOffset(2026, 1, 2, 12, 2, 0, TimeSpan.Zero);
        session.AdditionalVerificationProvider = new AuthenticationProviderKey(ProviderType.Mfa, "totp");
        session.AdditionalVerificationFactor = "totp";

        await sessionRepository.CreateSessionAsync(session);

        var fetched = await sessionRepository.GetSessionByTokenHashAsync(session.TokenHash);

        Assert.That(fetched, Is.Not.Null);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched.Id, Is.EqualTo(session.Id));
            Assert.That(fetched.UserId, Is.EqualTo(session.UserId));
            Assert.That(fetched.TenantId, Is.EqualTo(session.TenantId));
            Assert.That(fetched.TokenHash, Is.EqualTo(session.TokenHash));
            Assert.That(fetched.CreatedAt, Is.EqualTo(session.CreatedAt));
            Assert.That(fetched.AuthenticatedAt, Is.EqualTo(session.AuthenticatedAt));
            Assert.That(fetched.PrimaryProvider, Is.EqualTo(session.PrimaryProvider));
            Assert.That(fetched.AdditionalVerificationAt, Is.EqualTo(session.AdditionalVerificationAt));
            Assert.That(fetched.AdditionalVerificationProvider, Is.EqualTo(session.AdditionalVerificationProvider));
            Assert.That(fetched.AdditionalVerificationFactor, Is.EqualTo(session.AdditionalVerificationFactor));
            Assert.That(fetched.ExpiresAt, Is.EqualTo(session.ExpiresAt));
            Assert.That(fetched.LastSeenAt, Is.EqualTo(session.LastSeenAt));
            Assert.That(fetched.RevokedAt, Is.EqualTo(session.RevokedAt));
            Assert.That(fetched.RevocationReason, Is.EqualTo(session.RevocationReason));
            Assert.That(fetched.IpAddress, Is.EqualTo(session.IpAddress));
            Assert.That(fetched.UserAgent, Is.EqualTo(session.UserAgent));
            Assert.That(JsonNode.DeepEquals(JsonNode.Parse(fetched.Metadata!), JsonNode.Parse(session.Metadata!)), Is.True);
        }
    }

    [Test]
    public async Task GetSessionAsyncShouldReturnSessionById()
    {
        var userRepository = GetUserRepository();
        var sessionRepository = GetSessionRepository();
        var user = await CreateTestUser(userRepository);
        var session = CreateSession(user.Id);

        await sessionRepository.CreateSessionAsync(session);

        var fetched = await sessionRepository.GetSessionAsync(session.Id);

        Assert.That(fetched, Is.Not.Null);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched.Id, Is.EqualTo(session.Id));
            Assert.That(fetched.UserId, Is.EqualTo(user.Id));
        }
    }

    [Test]
    public async Task GetSessionAsyncShouldReturnNullWhenSessionIsMissing()
    {
        var sessionRepository = GetSessionRepository();

        var fetched = await sessionRepository.GetSessionAsync(Guid.NewGuid());

        Assert.That(fetched, Is.Null);
    }

    [Test]
    public async Task CreateSessionShouldRejectEmptySessionId()
    {
        var userRepository = GetUserRepository();
        var sessionRepository = GetSessionRepository();
        var user = await CreateTestUser(userRepository);
        var session = new AuthenticationSession
        {
            Id = Guid.Empty,
            UserId = user.Id,
            TokenHash = $"sha256:{Guid.NewGuid():N}",
            CreatedAt = new DateTimeOffset(2026, 1, 2, 12, 0, 0, TimeSpan.Zero),
            ExpiresAt = new DateTimeOffset(2026, 1, 3, 12, 0, 0, TimeSpan.Zero)
        };

        var exception = Assert.ThrowsAsync<ArgumentException>(async () => await sessionRepository.CreateSessionAsync(session));

        Assert.That(exception?.Message, Does.Contain("Session ID"));
    }

    [Test]
    public void CreateSessionShouldRejectEmptyUserId()
    {
        var sessionRepository = GetSessionRepository();
        var session = CreateSession(Guid.Empty);

        var exception = Assert.ThrowsAsync<ArgumentException>(async () => await sessionRepository.CreateSessionAsync(session));

        Assert.That(exception?.Message, Does.Contain("User ID"));
    }

    [Test]
    public async Task TokenHashUniquenessShouldBeEnforced()
    {
        var userRepository = GetUserRepository();
        var sessionRepository = GetSessionRepository();
        var user = await CreateTestUser(userRepository);
        var first = CreateSession(user.Id);
        var second = CreateSession(user.Id, first.TokenHash);

        await sessionRepository.CreateSessionAsync(first);

        Assert.ThrowsAsync<PostgresException>(async () => await sessionRepository.CreateSessionAsync(second));
    }

    [Test]
    public async Task CreateSessionShouldRejectInvalidMetadataJson()
    {
        var userRepository = GetUserRepository();
        var sessionRepository = GetSessionRepository();
        var user = await CreateTestUser(userRepository);
        var session = CreateSession(user.Id);
        session.Metadata = "not-json";

        var exception = Assert.ThrowsAsync<ArgumentException>(async () => await sessionRepository.CreateSessionAsync(session));

        Assert.That(exception?.Message, Does.Contain("metadata"));
    }

    [Test]
    public async Task UpdateSessionLastSeenShouldUpdateOnlyTargetSession()
    {
        var userRepository = GetUserRepository();
        var sessionRepository = GetSessionRepository();
        var user = await CreateTestUser(userRepository);
        var target = CreateSession(user.Id);
        var other = CreateSession(user.Id);
        var lastSeenAt = new DateTimeOffset(2026, 1, 2, 13, 0, 0, TimeSpan.Zero);

        await sessionRepository.CreateSessionAsync(target);
        await sessionRepository.CreateSessionAsync(other);

        var updated = await sessionRepository.UpdateSessionLastSeenAsync(target.Id, lastSeenAt);
        var fetchedTarget = await sessionRepository.GetSessionByTokenHashAsync(target.TokenHash);
        var fetchedOther = await sessionRepository.GetSessionByTokenHashAsync(other.TokenHash);

        Assert.That(updated, Is.True);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetchedTarget?.LastSeenAt, Is.EqualTo(lastSeenAt));
            Assert.That(fetchedOther?.LastSeenAt, Is.Null);
        }
    }

    [Test]
    public async Task UpdateSessionLastSeenShouldNotOverwriteNewerTimestamp()
    {
        var userRepository = GetUserRepository();
        var sessionRepository = GetSessionRepository();
        var user = await CreateTestUser(userRepository);
        var session = CreateSession(user.Id);
        var newerLastSeenAt = new DateTimeOffset(2026, 1, 2, 13, 0, 0, TimeSpan.Zero);
        var olderLastSeenAt = new DateTimeOffset(2026, 1, 2, 12, 30, 0, TimeSpan.Zero);

        await sessionRepository.CreateSessionAsync(session);

        var firstUpdated = await sessionRepository.UpdateSessionLastSeenAsync(session.Id, newerLastSeenAt);
        var secondUpdated = await sessionRepository.UpdateSessionLastSeenAsync(session.Id, olderLastSeenAt);
        var fetched = await sessionRepository.GetSessionByTokenHashAsync(session.TokenHash);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(firstUpdated, Is.True);
            Assert.That(secondUpdated, Is.False);
            Assert.That(fetched?.LastSeenAt, Is.EqualTo(newerLastSeenAt));
        }
    }

    [Test]
    public async Task UpdateSessionLastSeenShouldRejectRevokedSession()
    {
        var userRepository = GetUserRepository();
        var sessionRepository = GetSessionRepository();
        var user = await CreateTestUser(userRepository);
        var session = CreateSession(user.Id);
        var revokedAt = new DateTimeOffset(2026, 1, 2, 12, 30, 0, TimeSpan.Zero);
        var lastSeenAt = new DateTimeOffset(2026, 1, 2, 13, 0, 0, TimeSpan.Zero);

        await sessionRepository.CreateSessionAsync(session);
        await sessionRepository.RevokeSessionAsync(session.Id, revokedAt, "signed-out");

        var updated = await sessionRepository.UpdateSessionLastSeenAsync(session.Id, lastSeenAt);
        var fetched = await sessionRepository.GetSessionByTokenHashAsync(session.TokenHash);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(updated, Is.False);
            Assert.That(fetched?.LastSeenAt, Is.Null);
            Assert.That(fetched?.RevokedAt, Is.EqualTo(revokedAt));
        }
    }

    [Test]
    public async Task UpdateSessionLastSeenShouldRejectExpiredSession()
    {
        var userRepository = GetUserRepository();
        var sessionRepository = GetSessionRepository();
        var user = await CreateTestUser(userRepository);
        var expiresAt = new DateTimeOffset(2026, 1, 2, 12, 30, 0, TimeSpan.Zero);
        var session = CreateSession(user.Id, expiresAt: expiresAt);
        var lastSeenAt = new DateTimeOffset(2026, 1, 2, 13, 0, 0, TimeSpan.Zero);

        await sessionRepository.CreateSessionAsync(session);

        var updated = await sessionRepository.UpdateSessionLastSeenAsync(session.Id, lastSeenAt);
        var fetched = await sessionRepository.GetSessionByTokenHashAsync(session.TokenHash);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(updated, Is.False);
            Assert.That(fetched?.LastSeenAt, Is.Null);
            Assert.That(fetched?.ExpiresAt, Is.EqualTo(expiresAt));
        }
    }

    [Test]
    public async Task MarkStepUpVerifiedShouldUpdateOnlyActiveOwnedTargetSession()
    {
        var userRepository = GetUserRepository();
        var sessionRepository = GetSessionRepository();
        var owner = await CreateTestUser(userRepository);
        var otherUser = await CreateTestUser(userRepository);
        var target = CreateSession(owner.Id);
        var otherOwnerSession = CreateSession(owner.Id);
        var otherUserSession = CreateSession(otherUser.Id);
        var verifiedAt = new DateTimeOffset(2026, 1, 2, 13, 0, 0, TimeSpan.Zero);
        var provider = new AuthenticationProviderKey(ProviderType.Mfa, "totp");

        await sessionRepository.CreateSessionAsync(target);
        await sessionRepository.CreateSessionAsync(otherOwnerSession);
        await sessionRepository.CreateSessionAsync(otherUserSession);

        var updated = await sessionRepository.MarkStepUpVerifiedAsync(target.Id, owner.Id, verifiedAt, provider, "totp");
        var fetchedTarget = await sessionRepository.GetSessionByTokenHashAsync(target.TokenHash);
        var fetchedOtherOwner = await sessionRepository.GetSessionByTokenHashAsync(otherOwnerSession.TokenHash);
        var fetchedOtherUser = await sessionRepository.GetSessionByTokenHashAsync(otherUserSession.TokenHash);

        Assert.That(updated, Is.Not.Null);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(updated?.Id, Is.EqualTo(target.Id));
            Assert.That(fetchedTarget?.AdditionalVerificationAt, Is.EqualTo(verifiedAt));
            Assert.That(fetchedTarget?.AdditionalVerificationProvider, Is.EqualTo(provider));
            Assert.That(fetchedTarget?.AdditionalVerificationFactor, Is.EqualTo("totp"));
            Assert.That(fetchedOtherOwner?.AdditionalVerificationAt, Is.Null);
            Assert.That(fetchedOtherUser?.AdditionalVerificationAt, Is.Null);
        }
    }

    [Test]
    public async Task MarkStepUpVerifiedShouldRejectWrongUserRevokedAndExpiredSessions()
    {
        var userRepository = GetUserRepository();
        var sessionRepository = GetSessionRepository();
        var owner = await CreateTestUser(userRepository);
        var other = await CreateTestUser(userRepository);
        var active = CreateSession(owner.Id);
        var revoked = CreateSession(owner.Id);
        var expired = CreateSession(owner.Id, expiresAt: new DateTimeOffset(2026, 1, 2, 12, 30, 0, TimeSpan.Zero));
        var verifiedAt = new DateTimeOffset(2026, 1, 2, 13, 0, 0, TimeSpan.Zero);

        await sessionRepository.CreateSessionAsync(active);
        await sessionRepository.CreateSessionAsync(revoked);
        await sessionRepository.CreateSessionAsync(expired);
        await sessionRepository.RevokeSessionAsync(revoked.Id, verifiedAt.AddMinutes(-1), "test");

        var wrongUser = await sessionRepository.MarkStepUpVerifiedAsync(active.Id, other.Id, verifiedAt, AuthenticationProviderKey.Passkey, "passkey");
        var revokedUpdate = await sessionRepository.MarkStepUpVerifiedAsync(revoked.Id, owner.Id, verifiedAt, AuthenticationProviderKey.Passkey, "passkey");
        var expiredUpdate = await sessionRepository.MarkStepUpVerifiedAsync(expired.Id, owner.Id, verifiedAt, AuthenticationProviderKey.Passkey, "passkey");
        var fetchedActive = await sessionRepository.GetSessionByTokenHashAsync(active.TokenHash);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(wrongUser, Is.Null);
            Assert.That(revokedUpdate, Is.Null);
            Assert.That(expiredUpdate, Is.Null);
            Assert.That(fetchedActive?.AdditionalVerificationAt, Is.Null);
        }
    }

    [Test]
    public async Task RevokeSessionShouldRevokeOnlyTargetSession()
    {
        var userRepository = GetUserRepository();
        var sessionRepository = GetSessionRepository();
        var user = await CreateTestUser(userRepository);
        var target = CreateSession(user.Id);
        var other = CreateSession(user.Id);
        var revokedAt = new DateTimeOffset(2026, 1, 2, 14, 0, 0, TimeSpan.Zero);

        await sessionRepository.CreateSessionAsync(target);
        await sessionRepository.CreateSessionAsync(other);

        var revoked = await sessionRepository.RevokeSessionAsync(target.Id, revokedAt, "single");
        var fetchedTarget = await sessionRepository.GetSessionByTokenHashAsync(target.TokenHash);
        var fetchedOther = await sessionRepository.GetSessionByTokenHashAsync(other.TokenHash);

        Assert.That(revoked, Is.True);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetchedTarget?.RevokedAt, Is.EqualTo(revokedAt));
            Assert.That(fetchedTarget?.RevocationReason, Is.EqualTo("single"));
            Assert.That(fetchedOther?.RevokedAt, Is.Null);
            Assert.That(fetchedOther?.RevocationReason, Is.Null);
        }
    }

    [Test]
    public async Task RevokeSessionShouldNotOverwriteExistingRevocation()
    {
        var userRepository = GetUserRepository();
        var sessionRepository = GetSessionRepository();
        var user = await CreateTestUser(userRepository);
        var session = CreateSession(user.Id);
        var firstRevokedAt = new DateTimeOffset(2026, 1, 2, 14, 0, 0, TimeSpan.Zero);
        var secondRevokedAt = new DateTimeOffset(2026, 1, 2, 15, 0, 0, TimeSpan.Zero);

        await sessionRepository.CreateSessionAsync(session);
        var firstRevoked = await sessionRepository.RevokeSessionAsync(session.Id, firstRevokedAt, "manual");
        var secondRevoked = await sessionRepository.RevokeSessionAsync(session.Id, secondRevokedAt, "automated");
        var fetched = await sessionRepository.GetSessionByTokenHashAsync(session.TokenHash);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(firstRevoked, Is.True);
            Assert.That(secondRevoked, Is.False);
            Assert.That(fetched?.RevokedAt, Is.EqualTo(firstRevokedAt));
            Assert.That(fetched?.RevocationReason, Is.EqualTo("manual"));
        }
    }

    [Test]
    public async Task RevokeSessionsForUserShouldRevokeAllSessionsForTargetUser()
    {
        var userRepository = GetUserRepository();
        var sessionRepository = GetSessionRepository();
        var targetUser = await CreateTestUser(userRepository);
        var otherUser = await CreateTestUser(userRepository);
        var first = CreateSession(targetUser.Id);
        var second = CreateSession(targetUser.Id);
        var other = CreateSession(otherUser.Id);
        var revokedAt = new DateTimeOffset(2026, 1, 2, 15, 0, 0, TimeSpan.Zero);

        await sessionRepository.CreateSessionAsync(first);
        await sessionRepository.CreateSessionAsync(second);
        await sessionRepository.CreateSessionAsync(other);

        var count = await sessionRepository.RevokeSessionsForUserAsync(targetUser.Id, revokedAt, "all");

        var fetchedFirst = await sessionRepository.GetSessionByTokenHashAsync(first.TokenHash);
        var fetchedSecond = await sessionRepository.GetSessionByTokenHashAsync(second.TokenHash);
        var fetchedOther = await sessionRepository.GetSessionByTokenHashAsync(other.TokenHash);

        Assert.That(count, Is.EqualTo(2));
        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetchedFirst?.RevokedAt, Is.EqualTo(revokedAt));
            Assert.That(fetchedFirst?.RevocationReason, Is.EqualTo("all"));
            Assert.That(fetchedSecond?.RevokedAt, Is.EqualTo(revokedAt));
            Assert.That(fetchedSecond?.RevocationReason, Is.EqualTo("all"));
            Assert.That(fetchedOther?.RevokedAt, Is.Null);
        }
    }

    [Test]
    public async Task RevokeSessionsForUserShouldNotOverwriteExistingRevocations()
    {
        var userRepository = GetUserRepository();
        var sessionRepository = GetSessionRepository();
        var user = await CreateTestUser(userRepository);
        var alreadyRevoked = CreateSession(user.Id);
        var active = CreateSession(user.Id);
        var firstRevokedAt = new DateTimeOffset(2026, 1, 2, 14, 0, 0, TimeSpan.Zero);
        var secondRevokedAt = new DateTimeOffset(2026, 1, 2, 15, 0, 0, TimeSpan.Zero);

        await sessionRepository.CreateSessionAsync(alreadyRevoked);
        await sessionRepository.CreateSessionAsync(active);
        await sessionRepository.RevokeSessionAsync(alreadyRevoked.Id, firstRevokedAt, "manual");

        var count = await sessionRepository.RevokeSessionsForUserAsync(user.Id, secondRevokedAt, "bulk");

        var fetchedAlreadyRevoked = await sessionRepository.GetSessionByTokenHashAsync(alreadyRevoked.TokenHash);
        var fetchedActive = await sessionRepository.GetSessionByTokenHashAsync(active.TokenHash);

        Assert.That(count, Is.EqualTo(1));
        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetchedAlreadyRevoked?.RevokedAt, Is.EqualTo(firstRevokedAt));
            Assert.That(fetchedAlreadyRevoked?.RevocationReason, Is.EqualTo("manual"));
            Assert.That(fetchedActive?.RevokedAt, Is.EqualTo(secondRevokedAt));
            Assert.That(fetchedActive?.RevocationReason, Is.EqualTo("bulk"));
        }
    }

    [Test]
    public async Task ListSessionsForUserShouldReturnSessionsInCorrectOrder()
    {
        var userRepository = GetUserRepository();
        var sessionRepository = GetSessionRepository();
        var user = await CreateTestUser(userRepository);
        var first = CreateSession(user.Id, createdAt: new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
        var second = CreateSession(user.Id, createdAt: new DateTimeOffset(2026, 1, 2, 12, 0, 0, TimeSpan.Zero));

        await sessionRepository.CreateSessionAsync(first);
        await sessionRepository.CreateSessionAsync(second);

        var sessions = await sessionRepository.ListSessionsForUserAsync(user.Id, activeOnly: false, DateTimeOffset.UtcNow);

        Assert.That(sessions, Has.Count.EqualTo(2));
        using (Assert.EnterMultipleScope())
        {
            Assert.That(sessions[0].Id, Is.EqualTo(second.Id));
            Assert.That(sessions[1].Id, Is.EqualTo(first.Id));
        }
    }

    [Test]
    public async Task ListSessionsForUserShouldFilterActiveOnly()
    {
        var userRepository = GetUserRepository();
        var sessionRepository = GetSessionRepository();
        var user = await CreateTestUser(userRepository);
        var active = CreateSession(user.Id, expiresAt: DateTimeOffset.UtcNow.AddDays(1));
        var revoked = CreateSession(user.Id, expiresAt: DateTimeOffset.UtcNow.AddDays(1));
        var expired = CreateSession(user.Id, expiresAt: DateTimeOffset.UtcNow.AddHours(-1));

        await sessionRepository.CreateSessionAsync(active);
        await sessionRepository.CreateSessionAsync(revoked);
        await sessionRepository.CreateSessionAsync(expired);
        await sessionRepository.RevokeSessionAsync(revoked.Id, DateTimeOffset.UtcNow, "test");

        var sessions = await sessionRepository.ListSessionsForUserAsync(user.Id, activeOnly: true, DateTimeOffset.UtcNow);

        Assert.That(sessions, Has.Count.EqualTo(1));
        Assert.That(sessions[0].Id, Is.EqualTo(active.Id));
    }

    [Test]
    public async Task RevokeSessionByIdShouldEnforceOwnership()
    {
        var userRepository = GetUserRepository();
        var sessionRepository = GetSessionRepository();
        var owner = await CreateTestUser(userRepository);
        var other = await CreateTestUser(userRepository);
        var session = CreateSession(owner.Id);

        await sessionRepository.CreateSessionAsync(session);

        var revokedByOther = await sessionRepository.RevokeSessionByIdAsync(session.Id, other.Id, DateTimeOffset.UtcNow, "theft");
        var revokedByOwner = await sessionRepository.RevokeSessionByIdAsync(session.Id, owner.Id, DateTimeOffset.UtcNow, "done");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(revokedByOther, Is.False);
            Assert.That(revokedByOwner, Is.True);
        }
    }

    [Test]
    public async Task RevokeOtherSessionsForUserShouldPreserveCurrentSession()
    {
        var userRepository = GetUserRepository();
        var sessionRepository = GetSessionRepository();
        var user = await CreateTestUser(userRepository);
        var current = CreateSession(user.Id);
        var other1 = CreateSession(user.Id);
        var other2 = CreateSession(user.Id);

        await sessionRepository.CreateSessionAsync(current);
        await sessionRepository.CreateSessionAsync(other1);
        await sessionRepository.CreateSessionAsync(other2);

        var count = await sessionRepository.RevokeOtherSessionsForUserAsync(user.Id, current.Id, DateTimeOffset.UtcNow, "security-sweep");

        var fetchedCurrent = await sessionRepository.GetSessionByTokenHashAsync(current.TokenHash);
        var fetchedOther1 = await sessionRepository.GetSessionByTokenHashAsync(other1.TokenHash);
        var fetchedOther2 = await sessionRepository.GetSessionByTokenHashAsync(other2.TokenHash);

        Assert.That(count, Is.EqualTo(2));
        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetchedCurrent?.RevokedAt, Is.Null);
            Assert.That(fetchedOther1?.RevokedAt, Is.Not.Null);
            Assert.That(fetchedOther2?.RevokedAt, Is.Not.Null);
        }
    }

    [Test]
    public async Task DeletingUserShouldCascadeDeleteSessions()
    {
        var userRepository = GetUserRepository();
        var sessionRepository = GetSessionRepository();
        var user = await CreateTestUser(userRepository);
        var session = CreateSession(user.Id);

        await sessionRepository.CreateSessionAsync(session);
        await DeleteUserAsync(user.Id);

        var fetched = await sessionRepository.GetSessionByTokenHashAsync(session.TokenHash);

        Assert.That(fetched, Is.Null);
    }

    private IUserRepository GetUserRepository() => _serviceProvider.GetRequiredService<IUserRepository>();

    private PostgresAuthenticationSessionRepository GetSessionRepository()
    {
        return (PostgresAuthenticationSessionRepository)_serviceProvider.GetRequiredService<IAuthenticationSessionRepository>();
    }

    private async Task DeleteUserAsync(Guid userId)
    {
        await using var connection = await GetDataSource().OpenConnectionAsync();
        await using var command = new NpgsqlCommand("DELETE FROM ashlar_users WHERE id = @id", connection);
        command.Parameters.AddWithValue("id", userId);
        await command.ExecuteNonQueryAsync();
    }

    private static async Task<AshlarPostgresUser> CreateTestUser(IUserRepository repo, Guid? tenantId = null)
    {
        var user = new AshlarPostgresUser
        {
            Id = Guid.NewGuid(),
            Email = $"{Guid.NewGuid()}@example.com",
            AccountState = UserAccountState.Active,
            TenantId = tenantId,
            CreatedAt = DateTimeOffset.UtcNow
        };
        await repo.CreateUserAsync(user);
        return user;
    }

    private static AuthenticationSession CreateSession(
        Guid userId,
        string? tokenHash = null,
        DateTimeOffset? createdAt = null,
        DateTimeOffset? expiresAt = null,
        Guid? tenantId = null)
    {
        return new AuthenticationSession
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            TenantId = tenantId,
            TokenHash = tokenHash ?? $"sha256:{Guid.NewGuid():N}",
            CreatedAt = createdAt ?? new DateTimeOffset(2026, 1, 2, 12, 0, 0, TimeSpan.Zero),
            ExpiresAt = expiresAt ?? new DateTimeOffset(2026, 1, 3, 12, 0, 0, TimeSpan.Zero)
        };
    }
}
