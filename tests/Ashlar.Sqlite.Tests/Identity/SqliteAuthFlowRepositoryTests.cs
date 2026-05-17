using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.Models.Passkeys;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using System.Text.Json;

namespace Ashlar.Sqlite.Tests.Identity;

internal sealed class SqliteAuthFlowRepositoryTests : SqliteTestBase
{
    private ServiceProvider _serviceProvider = null!;

    [SetUp]
    public async Task SetUp()
    {
        var services = new ServiceCollection();
        services.AddAshlarSqlite(GetConnectionString());
        _serviceProvider = services.BuildServiceProvider();
        await _serviceProvider.InitializeAshlarSqliteSchemaAsync();
    }

    [TearDown]
    public async Task TearDownAsync()
    {
        await _serviceProvider.DisposeAsync();
    }

    [Test]
    public async Task InvitationsCreateFetchUpdateRevokeAndRejectTerminalOrExpiredRows()
    {
        var repository = GetInvitationRepository();
        var tenantId = Guid.NewGuid();
        var invitation = CreateInvitation("Invite@Example.com", "invite-token", tenantId: tenantId);
        invitation.Metadata = """{"source":"test"}""";

        await repository.CreateInvitationAsync(invitation);
        var fetched = await repository.GetInvitationByTokenHashAsync(invitation.TokenHash);

        Assert.That(fetched, Is.Not.Null);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched!.Email, Is.EqualTo(invitation.Email));
            Assert.That(fetched.TenantId, Is.EqualTo(tenantId));
            Assert.That(JsonDocument.Parse(fetched.Metadata!).RootElement.GetProperty("source").GetString(), Is.EqualTo("test"));
        }

        invitation.AcceptedAt = DateTimeOffset.UtcNow;
        var accepted = await repository.UpdateInvitationAsync(invitation, invitation.Version);
        var stale = await repository.UpdateInvitationAsync(invitation, "stale");
        var replay = await repository.UpdateInvitationAsync(invitation, invitation.Version);
        var acceptedFetched = await repository.GetInvitationByTokenHashAsync(invitation.TokenHash);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(accepted, Is.True);
            Assert.That(stale, Is.False);
            Assert.That(replay, Is.False);
            Assert.That(acceptedFetched!.AcceptedAt, Is.Not.Null);
        }

        var revokeTarget = CreateInvitation("tenant@example.com", "revoke-tenant", tenantId: tenantId);
        var otherTenant = CreateInvitation("tenant@example.com", "revoke-other", tenantId: Guid.NewGuid());
        var expired = CreateInvitation("expired@example.com", "expired-invite", createdAt: DateTimeOffset.UtcNow.AddDays(-2), expiresAt: DateTimeOffset.UtcNow.AddDays(-1));
        await repository.CreateInvitationAsync(revokeTarget);
        await repository.CreateInvitationAsync(otherTenant);
        await repository.CreateInvitationAsync(expired);

        var revoked = await repository.RevokeInvitationsByEmailAsync("TENANT@example.com", tenantId);
        expired.AcceptedAt = DateTimeOffset.UtcNow;
        var expiredAccepted = await repository.UpdateInvitationAsync(expired, expired.Version);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(revoked, Is.EqualTo(1));
            Assert.That((await repository.GetInvitationByTokenHashAsync(revokeTarget.TokenHash))!.RevokedAt, Is.Not.Null);
            Assert.That((await repository.GetInvitationByTokenHashAsync(otherTenant.TokenHash))!.RevokedAt, Is.Null);
            Assert.That(expiredAccepted, Is.False);
        }
    }

    [Test]
    public void InvitationRepositoryValidatesArguments()
    {
        Assert.Throws<ArgumentNullException>(() => _ = new SqliteInvitationRepository(null!));
        Assert.ThrowsAsync<ArgumentNullException>(async () => await GetInvitationRepository().CreateInvitationAsync(null!));
        Assert.ThrowsAsync<ArgumentException>(async () => await GetInvitationRepository().GetInvitationByTokenHashAsync(" "));

        var invalid = CreateInvitation("bad-json@example.com", "bad-json-invite");
        invalid.Metadata = "not-json";
        Assert.ThrowsAsync<ArgumentException>(async () => await GetInvitationRepository().CreateInvitationAsync(invalid));
        Assert.ThrowsAsync<ArgumentException>(async () => await GetInvitationRepository().UpdateInvitationAsync(invalid, invalid.Version));
    }

    [Test]
    public async Task SessionsPreserveActiveOwnershipMonotonicLastSeenRevocationAndStepUpSemantics()
    {
        var user = await CreateUserAsync();
        var otherUser = await CreateUserAsync();
        var repository = GetSessionRepository();
        var active = CreateSession(user.Id);
        active.AuthenticatedAt = active.CreatedAt.AddMinutes(1);
        active.PrimaryProvider = AuthenticationProviderKey.MagicLink;
        active.AdditionalVerificationAt = active.CreatedAt.AddMinutes(2);
        active.AdditionalVerificationProvider = new AuthenticationProviderKey(ProviderType.Mfa, "totp");
        active.AdditionalVerificationFactor = "totp";
        active.Metadata = """{"device":"laptop"}""";
        var revoked = CreateSession(user.Id);
        var expired = CreateSession(user.Id, expiresAt: DateTimeOffset.UtcNow.AddMinutes(-1));
        var other = CreateSession(otherUser.Id);
        await repository.CreateSessionAsync(active);
        await repository.CreateSessionAsync(revoked);
        await repository.CreateSessionAsync(expired);
        await repository.CreateSessionAsync(other);
        await repository.RevokeSessionAsync(revoked.Id, DateTimeOffset.UtcNow, "manual");

        var fetched = await repository.GetSessionByTokenHashAsync(active.TokenHash);
        var fetchedById = await repository.GetSessionAsync(active.Id);
        var listedActive = await repository.ListSessionsForUserAsync(user.Id, activeOnly: true, DateTimeOffset.UtcNow);
        var newest = DateTimeOffset.UtcNow.AddMinutes(1);
        var older = newest.AddMinutes(-1);
        var firstSeen = await repository.UpdateSessionLastSeenAsync(active.Id, newest);
        var secondSeen = await repository.UpdateSessionLastSeenAsync(active.Id, older);
        var stepUp = await repository.MarkStepUpVerifiedAsync(active.Id, user.Id, newest, AuthenticationProviderKey.Passkey, "passkey");
        var wrongUserStepUp = await repository.MarkStepUpVerifiedAsync(active.Id, otherUser.Id, newest, AuthenticationProviderKey.Passkey, "passkey");
        var revokeOther = await repository.RevokeOtherSessionsForUserAsync(user.Id, active.Id, newest, "sweep");
        var ownedRevoke = await repository.RevokeSessionByIdAsync(active.Id, otherUser.Id, newest, "wrong");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched, Is.Not.Null);
            Assert.That(fetched!.PrimaryProvider, Is.EqualTo(AuthenticationProviderKey.MagicLink));
            Assert.That(fetchedById!.Id, Is.EqualTo(active.Id));
            Assert.That(listedActive.Select(s => s.Id), Is.EquivalentTo(new[] { active.Id }));
            Assert.That(firstSeen, Is.True);
            Assert.That(secondSeen, Is.False);
            Assert.That(stepUp, Is.Not.Null);
            Assert.That(stepUp!.AdditionalVerificationProvider, Is.EqualTo(AuthenticationProviderKey.Passkey));
            Assert.That(stepUp.AdditionalVerificationFactor, Is.EqualTo("passkey"));
            Assert.That(wrongUserStepUp, Is.Null);
            Assert.That(revokeOther, Is.EqualTo(1));
            Assert.That(ownedRevoke, Is.False);
        }

        var allSessions = await repository.ListSessionsForUserAsync(user.Id, activeOnly: false, DateTimeOffset.UtcNow);
        var revokedAll = await repository.RevokeSessionsForUserAsync(otherUser.Id, DateTimeOffset.UtcNow, "all");
        var ownedRevokeAfterWrongUser = await repository.RevokeSessionByIdAsync(active.Id, user.Id, DateTimeOffset.UtcNow, "owned");
        using (Assert.EnterMultipleScope())
        {
            Assert.That(allSessions, Has.Count.EqualTo(3));
            Assert.That(revokedAll, Is.EqualTo(1));
            Assert.That(ownedRevokeAfterWrongUser, Is.True);
        }
    }

    [Test]
    public async Task SessionRepositoryValidatesArgumentsAndMissingRows()
    {
        var repository = GetSessionRepository();
        var user = await CreateUserAsync();

        Assert.Throws<ArgumentNullException>(() => _ = new SqliteAuthenticationSessionRepository(null!));
        Assert.ThrowsAsync<ArgumentNullException>(async () => await repository.CreateSessionAsync(null!));
        Assert.ThrowsAsync<ArgumentException>(async () => await repository.CreateSessionAsync(CreateSession(Guid.Empty)));
        Assert.ThrowsAsync<ArgumentException>(async () => await repository.CreateSessionAsync(new AuthenticationSession
        {
            Id = Guid.Empty,
            UserId = user.Id,
            TokenHash = $"sha256:{Guid.NewGuid():N}",
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(1)
        }));
        Assert.ThrowsAsync<ArgumentException>(async () => await repository.GetSessionByTokenHashAsync(" "));

        var invalidMetadata = CreateSession(user.Id);
        invalidMetadata.Metadata = "not-json";
        Assert.ThrowsAsync<ArgumentException>(async () => await repository.CreateSessionAsync(invalidMetadata));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(await repository.GetSessionAsync(Guid.NewGuid()), Is.Null);
            Assert.That(await repository.GetSessionByTokenHashAsync($"missing:{Guid.NewGuid():N}"), Is.Null);
        }
    }

    [Test]
    public async Task HandshakesCreateFetchForUpdateAndPersistCompletionRevocationAndJsonState()
    {
        var user = await CreateUserAsync();
        var repository = GetHandshakeRepository();
        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            user.Id,
            "handshake-token",
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddMinutes(5),
            false,
            false,
            new HashSet<string> { "totp", "passkey" },
            new HashSet<string>(),
            new Dictionary<string, string> { ["flow"] = "step-up" });

        await repository.CreateAsync(handshake);
        var fetched = await repository.FindByTokenHashAsync(handshake.TokenHash, forUpdate: true);
        var updated = handshake with
        {
            IsCompleted = true,
            IsRevoked = true,
            VerifiedFactors = new HashSet<string> { "totp", "passkey" },
            Metadata = new Dictionary<string, string> { ["done"] = "true" }
        };

        await repository.UpdateAsync(updated);
        var afterUpdate = await repository.FindByTokenHashAsync(handshake.TokenHash);
        var expired = new AuthenticationHandshake(Guid.NewGuid(), user.Id, "expired-handshake", DateTimeOffset.UtcNow.AddHours(-2), DateTimeOffset.UtcNow.AddHours(-1), false, false, new HashSet<string> { "totp" }, new HashSet<string>());
        await repository.CreateAsync(expired);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched, Is.Not.Null);
            Assert.That(fetched!.RequiredFactors, Is.EquivalentTo(handshake.RequiredFactors));
            Assert.That(afterUpdate!.IsCompleted, Is.True);
            Assert.That(afterUpdate.IsRevoked, Is.True);
            Assert.That(afterUpdate.CompletedAt, Is.Not.Null);
            Assert.That(afterUpdate.RevokedAt, Is.Not.Null);
            Assert.That(afterUpdate.VerifiedFactors, Is.EquivalentTo(updated.VerifiedFactors));
            Assert.That((await repository.FindByTokenHashAsync(expired.TokenHash))!.ExpiresAt, Is.EqualTo(expired.ExpiresAt));
        }
    }

    [Test]
    public async Task HandshakeRepositoryCoversNullAndFalseStateBranches()
    {
        var user = await CreateUserAsync();
        var repository = GetHandshakeRepository();
        var terminal = new AuthenticationHandshake(
            Guid.NewGuid(),
            user.Id,
            "terminal-handshake",
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddMinutes(5),
            true,
            true,
            new HashSet<string> { "totp" },
            new HashSet<string> { "totp" });

        await repository.CreateAsync(terminal);
        var fetched = await repository.FindByTokenHashAsync(terminal.TokenHash);
        await repository.UpdateAsync(terminal with { IsRevoked = false, IsCompleted = false, VerifiedFactors = new HashSet<string>(), Metadata = null });
        var terminalAfterStaleUpdate = await repository.FindByTokenHashAsync(terminal.TokenHash);

        var resettable = new AuthenticationHandshake(
            Guid.NewGuid(),
            user.Id,
            "resettable-handshake",
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddMinutes(5),
            false,
            false,
            new HashSet<string> { "totp" },
            new HashSet<string>());
        await repository.CreateAsync(resettable);
        await repository.UpdateAsync(resettable with { IsRevoked = false, IsCompleted = false, VerifiedFactors = new HashSet<string>(), Metadata = null });
        var reset = await repository.FindByTokenHashAsync(resettable.TokenHash);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched!.RevokedAt, Is.Not.Null);
            Assert.That(fetched.CompletedAt, Is.Not.Null);
            Assert.That(terminalAfterStaleUpdate!.IsRevoked, Is.True);
            Assert.That(terminalAfterStaleUpdate.IsCompleted, Is.True);
            Assert.That(reset!.IsRevoked, Is.False);
            Assert.That(reset.IsCompleted, Is.False);
            Assert.That(reset.RevokedAt, Is.Null);
            Assert.That(reset.CompletedAt, Is.Null);
            Assert.That(reset.Metadata, Is.Null);
            Assert.That(await repository.FindByTokenHashAsync($"missing:{Guid.NewGuid():N}"), Is.Null);
        }

        Assert.Throws<ArgumentNullException>(() => _ = new SqliteAuthenticationHandshakeRepository(null!));
        Assert.ThrowsAsync<ArgumentNullException>(async () => await repository.CreateAsync(null!));
        Assert.ThrowsAsync<ArgumentNullException>(async () => await repository.UpdateAsync(null!));
        Assert.ThrowsAsync<ArgumentException>(async () => await repository.FindByTokenHashAsync(" "));

        await InsertHandshakeWithNullFactorJsonAsync(user.Id, "null-factor-json");
        var nullFactors = await repository.FindByTokenHashAsync("null-factor-json");
        using (Assert.EnterMultipleScope())
        {
            Assert.That(nullFactors!.RequiredFactors, Is.Empty);
            Assert.That(nullFactors.VerifiedFactors, Is.Empty);
        }
    }

    [Test]
    public async Task PasskeyChallengesCreateFetchConsumeAtomicallyAndEnforcePurposeShape()
    {
        var user = await CreateUserAsync();
        var repository = GetPasskeyRepository();
        var registration = CreateChallenge(user.Id, purpose: "passkey-registration", handshakeTokenHash: null, factorType: null);
        var authentication = CreateChallenge(user.Id, purpose: "passkey-authentication", handshakeTokenHash: "hashed-handshake", factorType: "passkey");
        var expired = CreateChallenge(user.Id, expiresAt: DateTimeOffset.UtcNow.AddMinutes(-1));
        await repository.CreateAsync(registration);
        await repository.CreateAsync(authentication);
        await repository.CreateAsync(expired);

        var fetched = await repository.GetAsync(authentication.Id);
        var consumed = await repository.ConsumeAsync(authentication.Id, authentication.Version, DateTimeOffset.UtcNow);
        var secondConsume = await repository.ConsumeAsync(authentication.Id, authentication.Version, DateTimeOffset.UtcNow);
        var stale = await repository.ConsumeAsync(registration.Id, "stale", DateTimeOffset.UtcNow);
        var expiredConsumed = await repository.ConsumeAsync(expired.Id, expired.Version, DateTimeOffset.UtcNow);
        var consumedFetched = await repository.GetAsync(authentication.Id);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched, Is.Not.Null);
            Assert.That(fetched!.Purpose, Is.EqualTo("passkey-authentication"));
            Assert.That(consumed, Is.True);
            Assert.That(secondConsume, Is.False);
            Assert.That(stale, Is.False);
            Assert.That(expiredConsumed, Is.False);
            Assert.That(consumedFetched!.ConsumedAt, Is.Not.Null);
            Assert.That(consumedFetched.Version, Is.Not.EqualTo(authentication.Version));
        }

        var invalidRegistration = CreateChallenge(null, purpose: "passkey-registration", handshakeTokenHash: null, factorType: null);
        Assert.ThrowsAsync<SqliteException>(async () => await repository.CreateAsync(invalidRegistration));
    }

    [Test]
    public async Task PasskeyRepositoryValidatesArgumentsAndMissingRows()
    {
        var repository = GetPasskeyRepository();
        Assert.Throws<ArgumentNullException>(() => _ = new SqlitePasskeyChallengeRepository(null!));
        Assert.ThrowsAsync<ArgumentNullException>(async () => await repository.CreateAsync(null!));
        Assert.ThrowsAsync<ArgumentException>(async () => await repository.ConsumeAsync(Guid.NewGuid(), " ", DateTimeOffset.UtcNow));
        Assert.That(await repository.GetAsync(Guid.NewGuid()), Is.Null);
    }

    [Test]
    public async Task InvitationCreateRollsBackWithTransaction()
    {
        var invitation = CreateInvitation("rollback@example.com", "rollback-token");

        await using (var scope = _serviceProvider.CreateAsyncScope())
        {
            var transactionProvider = scope.ServiceProvider.GetRequiredService<IAshlarTransactionProvider>();
            var repository = scope.ServiceProvider.GetRequiredService<IInvitationRepository>();
            await using var transaction = await transactionProvider.BeginTransactionAsync();
            await repository.CreateInvitationAsync(invitation);
            await transaction.RollbackAsync();
        }

        Assert.That(await GetInvitationRepository().GetInvitationByTokenHashAsync(invitation.TokenHash), Is.Null);
    }

    private IInvitationRepository GetInvitationRepository() => _serviceProvider.GetRequiredService<IInvitationRepository>();

    private IAuthenticationSessionRepository GetSessionRepository() => _serviceProvider.GetRequiredService<IAuthenticationSessionRepository>();

    private IAuthenticationHandshakeRepository GetHandshakeRepository() => _serviceProvider.GetRequiredService<IAuthenticationHandshakeRepository>();

    private IPasskeyChallengeRepository GetPasskeyRepository() => _serviceProvider.GetRequiredService<IPasskeyChallengeRepository>();

    private async Task<AshlarUser> CreateUserAsync()
    {
        var user = new AshlarUser
        {
            Id = Guid.NewGuid(),
            Email = $"{Guid.NewGuid():N}@example.com",
            IsActive = true
        };
        await _serviceProvider.GetRequiredService<IIdentityRepository>().CreateUserAsync(user);
        return user;
    }

    private static UserInvitation CreateInvitation(string email, string tokenHash, Guid? tenantId = null, DateTimeOffset? createdAt = null, DateTimeOffset? expiresAt = null)
    {
        var created = createdAt ?? DateTimeOffset.UtcNow;
        return new UserInvitation
        {
            Id = Guid.NewGuid(),
            Email = email,
            TenantId = tenantId,
            TokenHash = tokenHash,
            CreatedAt = created,
            ExpiresAt = expiresAt ?? created.AddDays(7),
            Version = Guid.NewGuid().ToString("N")
        };
    }

    private static AuthenticationSession CreateSession(Guid userId, DateTimeOffset? expiresAt = null)
    {
        var now = DateTimeOffset.UtcNow;
        var createdAt = expiresAt.HasValue && expiresAt.Value < now ? expiresAt.Value.AddHours(-1) : now;
        return new AuthenticationSession
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            TokenHash = $"sha256:{Guid.NewGuid():N}",
            CreatedAt = createdAt,
            ExpiresAt = expiresAt ?? now.AddDays(1)
        };
    }

    private static PasskeyChallenge CreateChallenge(
        Guid? userId,
        string purpose = "passkey-authentication",
        DateTimeOffset? expiresAt = null,
        string? handshakeTokenHash = null,
        string? factorType = null)
    {
        var now = DateTimeOffset.UtcNow;
        return new PasskeyChallenge
        {
            Id = Guid.NewGuid(),
            Version = Guid.NewGuid().ToString("N"),
            Purpose = purpose,
            UserId = userId,
            HandshakeTokenHash = handshakeTokenHash,
            FactorType = factorType,
            DisplayName = purpose == "passkey-registration" ? "Work Laptop" : null,
            Challenge = Guid.NewGuid().ToString("N"),
            OptionsJson = """{"challenge":"test"}""",
            RelyingPartyId = "example.com",
            Origin = "https://example.com",
            CreatedAt = expiresAt.HasValue && expiresAt.Value < now ? now.AddMinutes(-10) : now,
            ExpiresAt = expiresAt ?? now.AddMinutes(5)
        };
    }

    private async Task InsertHandshakeWithNullFactorJsonAsync(Guid userId, string tokenHash)
    {
        await using var connection = await OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO ashlar_mfa_handshakes (id, user_id, token_hash, created_at, expires_at, required_factors, verified_factors)
            VALUES ($id, $userId, $tokenHash, $createdAt, $expiresAt, 'null', 'null');
            """;
        command.AddGuidParameter("$id", Guid.NewGuid());
        command.AddGuidParameter("$userId", userId);
        command.AddParameter("$tokenHash", tokenHash);
        command.AddDateTimeOffsetParameter("$createdAt", DateTimeOffset.UtcNow);
        command.AddDateTimeOffsetParameter("$expiresAt", DateTimeOffset.UtcNow.AddMinutes(5));
        await command.ExecuteNonQueryAsync();
    }
}
