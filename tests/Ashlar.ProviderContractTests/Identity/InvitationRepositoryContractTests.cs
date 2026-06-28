using System.Text.Json.Nodes;

namespace Ashlar.ProviderContractTests.Identity;

internal abstract class InvitationRepositoryContractTests : ProviderContractFixture
{
    protected static readonly DateTimeOffset RepositoryNow = new(2026, 6, 3, 12, 0, 0, TimeSpan.Zero);

    private static readonly DateTimeOffset CreatedAt = new(2026, 6, 2, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task CreateAndFetchInvitationByTokenHashMapsFields()
    {
        await using var scope = CreateAsyncScope();
        var repository = GetInvitationRepository(scope.ServiceProvider);
        var tenantId = Guid.NewGuid();
        var invitation = CreateInvitation("Invite@Example.com", "invite-token", tenantId);
        invitation.Metadata = """{"source":"contract"}""";

        await repository.CreateInvitationAsync(invitation);

        var fetched = await repository.GetInvitationByTokenHashAsync(invitation.TokenHash);

        Assert.That(fetched, Is.Not.Null);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched!.Id, Is.EqualTo(invitation.Id));
            Assert.That(fetched.DisplayEmail, Is.EqualTo(invitation.DisplayEmail));
            Assert.That(fetched.TenantId, Is.EqualTo(tenantId));
            Assert.That(fetched.TokenHash, Is.EqualTo(invitation.TokenHash));
            Assert.That(fetched.CreatedAt, Is.EqualTo(invitation.CreatedAt));
            Assert.That(fetched.ExpiresAt, Is.EqualTo(invitation.ExpiresAt));
            Assert.That(fetched.Version, Is.EqualTo(invitation.Version));
            Assert.That(JsonEquals(fetched.Metadata, invitation.Metadata), Is.True);
        }
    }

    [Test]
    public async Task MissingTokenReturnsNull()
    {
        await using var scope = CreateAsyncScope();
        var repository = GetInvitationRepository(scope.ServiceProvider);

        Assert.That(await repository.GetInvitationByTokenHashAsync("missing-token"), Is.Null);
    }

    [Test]
    public async Task VersionedUpdateSucceedsWithCorrectVersionAndFailsWithStaleVersion()
    {
        await using var scope = CreateAsyncScope();
        var repository = GetInvitationRepository(scope.ServiceProvider);
        var invitation = CreateInvitation("versioned@example.com", "versioned-token");
        await repository.CreateInvitationAsync(invitation);
        var fetched = await repository.GetInvitationByTokenHashAsync(invitation.TokenHash);
        Assert.That(fetched, Is.Not.Null);

        var expectedVersion = fetched!.Version;
        fetched.Metadata = """{"updated":true}""";

        var updated = await repository.UpdateInvitationAsync(fetched, expectedVersion);
        var stale = await repository.UpdateInvitationAsync(fetched, expectedVersion);
        var afterUpdate = await repository.GetInvitationByTokenHashAsync(invitation.TokenHash);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(updated, Is.True);
            Assert.That(stale, Is.False);
            Assert.That(afterUpdate!.AcceptedAt, Is.Null);
            Assert.That(afterUpdate.RevokedAt, Is.Null);
            Assert.That(JsonEquals(afterUpdate.Metadata, fetched.Metadata), Is.True);
            Assert.That(afterUpdate.Version, Is.Not.EqualTo(expectedVersion));
        }
    }

    [Test]
    public async Task AcceptedInvitationCannotBeAcceptedAgain()
    {
        await using var scope = CreateAsyncScope();
        var repository = GetInvitationRepository(scope.ServiceProvider);
        var invitation = CreateInvitation("accepted@example.com", "accepted-token");
        await repository.CreateInvitationAsync(invitation);
        var fetched = (await repository.GetInvitationByTokenHashAsync(invitation.TokenHash))!;

        fetched.AcceptedAt = CreatedAt.AddHours(1);
        var first = await repository.UpdateInvitationAsync(fetched, fetched.Version);
        var accepted = await repository.GetInvitationByTokenHashAsync(invitation.TokenHash);
        accepted!.AcceptedAt = CreatedAt.AddHours(2);
        var second = await repository.UpdateInvitationAsync(accepted, accepted.Version);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(first, Is.True);
            Assert.That(second, Is.False);
        }
    }

    [Test]
    public async Task RevokedInvitationCannotBeAccepted()
    {
        await using var scope = CreateAsyncScope();
        var repository = GetInvitationRepository(scope.ServiceProvider);
        var invitation = CreateInvitation("revoked@example.com", "revoked-token");
        await repository.CreateInvitationAsync(invitation);
        Assert.That(await repository.RevokeInvitationsByEmailAsync(invitation.DisplayEmail), Is.EqualTo(1));

        var revoked = await repository.GetInvitationByTokenHashAsync(invitation.TokenHash);
        revoked!.AcceptedAt = CreatedAt.AddHours(1);
        var accepted = await repository.UpdateInvitationAsync(revoked, revoked.Version);

        Assert.That(accepted, Is.False);
    }

    [Test]
    public async Task ExpiredInvitationCannotBeAccepted()
    {
        await using var scope = CreateAsyncScope();
        var repository = GetInvitationRepository(scope.ServiceProvider);
        var invitation = CreateInvitation(
            "expired@example.com",
            "expired-token",
            createdAt: RepositoryNow.AddDays(-2),
            expiresAt: RepositoryNow.AddDays(-1));
        await repository.CreateInvitationAsync(invitation);

        invitation.AcceptedAt = RepositoryNow;
        var accepted = await repository.UpdateInvitationAsync(invitation, invitation.Version);

        Assert.That(accepted, Is.False);
    }

    [Test]
    public async Task RevokeByEmailIsCaseInsensitiveTenantScopedAndDoesNotAffectOtherTenants()
    {
        await using var scope = CreateAsyncScope();
        var repository = GetInvitationRepository(scope.ServiceProvider);
        var tenantId = Guid.NewGuid();
        var otherTenantId = Guid.NewGuid();
        var target = CreateInvitation("Tenant@Example.com", "tenant-token", tenantId);
        var otherTenant = CreateInvitation("tenant@example.com", "other-tenant-token", otherTenantId);
        var noTenant = CreateInvitation("tenant@example.com", "no-tenant-token");
        await repository.CreateInvitationAsync(target);
        await repository.CreateInvitationAsync(otherTenant);
        await repository.CreateInvitationAsync(noTenant);

        var revoked = await repository.RevokeInvitationsByEmailAsync("TENANT@example.com", tenantId);
        var fetchedTarget = await repository.GetInvitationByTokenHashAsync(target.TokenHash);
        var fetchedOtherTenant = await repository.GetInvitationByTokenHashAsync(otherTenant.TokenHash);
        var fetchedNoTenant = await repository.GetInvitationByTokenHashAsync(noTenant.TokenHash);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(revoked, Is.EqualTo(1));
            Assert.That(fetchedTarget!.RevokedAt, Is.Not.Null);
            Assert.That(fetchedOtherTenant!.RevokedAt, Is.Null);
            Assert.That(fetchedNoTenant!.RevokedAt, Is.Null);
        }
    }

    [Test]
    public async Task InvitationWritesRollBackWhenProviderSupportsTransactions()
    {
        var invitation = CreateInvitation("rollback@example.com", "rollback-token");
        await using (var scope = CreateAsyncScope())
        {
            var transactionProvider = GetTransactionProvider(scope.ServiceProvider);
            if (transactionProvider == null)
            {
                Assert.Ignore("Provider does not register IAshlarTransactionProvider.");
            }

            var repository = GetInvitationRepository(scope.ServiceProvider);
            await using var transaction = await transactionProvider.BeginTransactionAsync();
            await repository.CreateInvitationAsync(invitation);
            await transaction.RollbackAsync();
        }

        await using var verificationScope = CreateAsyncScope();
        var verificationRepository = GetInvitationRepository(verificationScope.ServiceProvider);
        Assert.That(await verificationRepository.GetInvitationByTokenHashAsync(invitation.TokenHash), Is.Null);
    }

    [Test]
    public async Task AdministrationSearchFiltersByTenantGlobalAndAllTenants()
    {
        await using var scope = CreateAsyncScope();
        var repository = GetInvitationRepository(scope.ServiceProvider);
        var tenantId = Guid.NewGuid();
        var tenantInvitation = CreateInvitation("admin-scope@example.com", "admin-scope-tenant", tenantId);
        var globalInvitation = CreateInvitation("admin-scope@example.com", "admin-scope-global");
        await repository.CreateInvitationAsync(tenantInvitation);
        await repository.CreateInvitationAsync(globalInvitation);

        var tenant = await repository.SearchInvitationsAsync(new SearchInvitationsRequest { Tenant = new TenantContext(tenantId), Email = "ADMIN-SCOPE@example.com", Limit = 10 }, RepositoryNow);
        var global = await repository.SearchInvitationsAsync(new SearchInvitationsRequest { Tenant = TenantContext.Global, Email = "admin-scope@example.com", Limit = 10 }, RepositoryNow);
        var all = await repository.SearchInvitationsAsync(new SearchInvitationsRequest { IncludeAllTenants = true, Email = "admin-scope@example.com", Limit = 10 }, RepositoryNow);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(tenant.Select(invitation => invitation.Id), Is.EqualTo(new[] { tenantInvitation.Id }));
            Assert.That(global.Select(invitation => invitation.Id), Is.EqualTo(new[] { globalInvitation.Id }));
            Assert.That(all.Select(invitation => invitation.Id), Is.EquivalentTo(new[] { tenantInvitation.Id, globalInvitation.Id }));
        }
    }

    [Test]
    public async Task AdministrationSearchFiltersByEmailStatusAndTimeRanges()
    {
        await using var scope = CreateAsyncScope();
        var repository = GetInvitationRepository(scope.ServiceProvider);
        var pending = CreateInvitation("filter-pending@example.com", "filter-pending", createdAt: CreatedAt, expiresAt: RepositoryNow.AddDays(1));
        var accepted = CreateInvitation("filter-accepted@example.com", "filter-accepted", createdAt: CreatedAt.AddHours(1), expiresAt: RepositoryNow.AddDays(1));
        var revoked = CreateInvitation("filter-revoked@example.com", "filter-revoked", createdAt: CreatedAt.AddHours(2), expiresAt: RepositoryNow.AddDays(1));
        var expired = CreateInvitation("filter-expired@example.com", "filter-expired", createdAt: RepositoryNow.AddDays(-3), expiresAt: RepositoryNow.AddDays(-1));
        await repository.CreateInvitationAsync(pending);
        await repository.CreateInvitationAsync(accepted);
        await repository.CreateInvitationAsync(revoked);
        await repository.CreateInvitationAsync(expired);
        accepted.AcceptedAt = RepositoryNow.AddMinutes(-30);
        var acceptedUpdated = await repository.UpdateInvitationAsync(accepted, accepted.Version);
        var revokedCount = await repository.RevokeInvitationsByEmailAsync(revoked.DisplayEmail);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(acceptedUpdated, Is.True);
            Assert.That(revokedCount, Is.EqualTo(1));
        }

        var emailQuery = await repository.SearchInvitationsAsync(new SearchInvitationsRequest { IncludeAllTenants = true, EmailQuery = "FILTER-PENDING", Limit = 10 }, RepositoryNow);
        var pendingStatus = await repository.SearchInvitationsAsync(new SearchInvitationsRequest { IncludeAllTenants = true, EmailQuery = "filter-", Status = InvitationAdministrationStatus.Pending, Limit = 10 }, RepositoryNow);
        var acceptedRange = await repository.SearchInvitationsAsync(new SearchInvitationsRequest { IncludeAllTenants = true, AcceptedFrom = RepositoryNow.AddHours(-1), AcceptedTo = RepositoryNow, Limit = 10 }, RepositoryNow);
        var revokedRange = await repository.SearchInvitationsAsync(new SearchInvitationsRequest { IncludeAllTenants = true, RevokedFrom = RepositoryNow.AddMinutes(-1), RevokedTo = RepositoryNow.AddMinutes(1), Limit = 10 }, RepositoryNow);
        var expiredRange = await repository.SearchInvitationsAsync(new SearchInvitationsRequest { IncludeAllTenants = true, Status = InvitationAdministrationStatus.Expired, ExpiresTo = RepositoryNow, Limit = 10 }, RepositoryNow);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(emailQuery.Select(invitation => invitation.Id), Is.EqualTo(new[] { pending.Id }));
            Assert.That(pendingStatus.Select(invitation => invitation.Id), Is.EqualTo(new[] { pending.Id }));
            Assert.That(acceptedRange.Select(invitation => invitation.Id), Does.Contain(accepted.Id));
            Assert.That(revokedRange.Select(invitation => invitation.Id), Does.Contain(revoked.Id));
            Assert.That(expiredRange.Select(invitation => invitation.Id), Does.Contain(expired.Id));
        }
    }

    [Test]
    public async Task AdministrationSearchSupportsPaging()
    {
        await using var scope = CreateAsyncScope();
        var repository = GetInvitationRepository(scope.ServiceProvider);
        List<UserInvitation> invitations = [];
        for (var i = 0; i < 4; i++)
        {
            var invitation = CreateInvitation($"admin-page-{i}@example.com", $"admin-page-{i}", createdAt: CreatedAt.AddMinutes(i));
            invitations.Add(invitation);
            await repository.CreateInvitationAsync(invitation);
        }

        var result = await repository.SearchInvitationsAsync(new SearchInvitationsRequest { IncludeAllTenants = true, EmailQuery = "admin-page-", Limit = 2, Offset = 1 }, RepositoryNow);
        var expected = invitations.OrderByDescending(invitation => invitation.CreatedAt).ThenByDescending(invitation => invitation.Id).Skip(1).Take(2).Select(invitation => invitation.Id);

        Assert.That(result.Select(invitation => invitation.Id), Is.EqualTo(expected));
    }

    [Test]
    public async Task AdministrationLookupAppliesTenantIsolationAndDoesNotExposeSecrets()
    {
        await using var scope = CreateAsyncScope();
        var repository = GetInvitationRepository(scope.ServiceProvider);
        var tenantId = Guid.NewGuid();
        var otherTenantId = Guid.NewGuid();
        var invitation = CreateInvitation("admin-lookup@example.com", "admin-lookup-token", tenantId);
        invitation.Metadata = """{"safe":true}""";
        await repository.CreateInvitationAsync(invitation);

        var inScope = await repository.GetInvitationAsync(new InvitationAdministrationLookupRequest(invitation.Id, new TenantContext(tenantId)), RepositoryNow);
        var outOfScope = await repository.GetInvitationAsync(new InvitationAdministrationLookupRequest(invitation.Id, new TenantContext(otherTenantId)), RepositoryNow);
        var globalScope = await repository.GetInvitationAsync(new InvitationAdministrationLookupRequest(invitation.Id, TenantContext.Global), RepositoryNow);
        var allTenants = await repository.GetInvitationAsync(new InvitationAdministrationLookupRequest(invitation.Id, IncludeAllTenants: true), RepositoryNow);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(inScope?.Id, Is.EqualTo(invitation.Id));
            Assert.That(outOfScope, Is.Null);
            Assert.That(globalScope, Is.Null);
            Assert.That(allTenants?.Id, Is.EqualTo(invitation.Id));
            Assert.That(typeof(InvitationAdministrationSummary).GetProperties().Select(static property => property.Name), Does.Not.Contain("TokenHash"));
            Assert.That(typeof(InvitationAdministrationSummary).GetProperties().Select(static property => property.Name), Does.Not.Contain("Metadata"));
        }
    }

    [Test]
    public async Task AdministrationRevokeByIdIsTenantScopedAndReportsTerminalStates()
    {
        await using var scope = CreateAsyncScope();
        var repository = GetInvitationRepository(scope.ServiceProvider);
        var tenantId = Guid.NewGuid();
        var otherTenantId = Guid.NewGuid();
        var invitation = CreateInvitation("admin-revoke@example.com", "admin-revoke-token", tenantId);
        var accepted = CreateInvitation("admin-revoke-accepted@example.com", "admin-revoke-accepted", tenantId);
        var expired = CreateInvitation("admin-revoke-expired@example.com", "admin-revoke-expired", tenantId, expiresAt: RepositoryNow.AddMinutes(-1));
        await repository.CreateInvitationAsync(invitation);
        await repository.CreateInvitationAsync(accepted);
        await repository.CreateInvitationAsync(expired);
        accepted.AcceptedAt = RepositoryNow.AddMinutes(-10);
        Assert.That(await repository.UpdateInvitationAsync(accepted, accepted.Version), Is.True);

        var outOfScope = await repository.RevokeInvitationAsync(new RevokeInvitationAdministrationRequest(invitation.Id, new TenantContext(otherTenantId), Audit: CreateAudit()), RepositoryNow);
        var revoked = await repository.RevokeInvitationAsync(new RevokeInvitationAdministrationRequest(invitation.Id, new TenantContext(tenantId), Audit: CreateAudit()), RepositoryNow);
        var second = await repository.RevokeInvitationAsync(new RevokeInvitationAdministrationRequest(invitation.Id, new TenantContext(tenantId), Audit: CreateAudit()), RepositoryNow);
        var terminal = await repository.RevokeInvitationAsync(new RevokeInvitationAdministrationRequest(accepted.Id, new TenantContext(tenantId), Audit: CreateAudit()), RepositoryNow);
        var expiredTerminal = await repository.RevokeInvitationAsync(new RevokeInvitationAdministrationRequest(expired.Id, new TenantContext(tenantId), Audit: CreateAudit()), RepositoryNow);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(outOfScope, Is.Null);
            Assert.That(revoked?.RevocationStatus, Is.EqualTo(InvitationAdministrationRevocationStatus.Revoked));
            Assert.That(revoked?.TenantId, Is.EqualTo(tenantId));
            Assert.That(revoked?.Status, Is.EqualTo(InvitationAdministrationStatus.Revoked));
            Assert.That(second?.RevocationStatus, Is.EqualTo(InvitationAdministrationRevocationStatus.AlreadyRevoked));
            Assert.That(second?.TenantId, Is.EqualTo(tenantId));
            Assert.That(second?.Status, Is.EqualTo(InvitationAdministrationStatus.Revoked));
            Assert.That(terminal?.RevocationStatus, Is.EqualTo(InvitationAdministrationRevocationStatus.AlreadyAccepted));
            Assert.That(terminal?.TenantId, Is.EqualTo(tenantId));
            Assert.That(terminal?.Status, Is.EqualTo(InvitationAdministrationStatus.Accepted));
            Assert.That(expiredTerminal?.RevocationStatus, Is.EqualTo(InvitationAdministrationRevocationStatus.Expired));
            Assert.That(expiredTerminal?.TenantId, Is.EqualTo(tenantId));
            Assert.That(expiredTerminal?.Status, Is.EqualTo(InvitationAdministrationStatus.Expired));
        }
    }

    [Test]
    public async Task AdministrationSearchRejectsInvalidPaging()
    {
        await using var scope = CreateAsyncScope();
        var repository = GetInvitationRepository(scope.ServiceProvider);

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => repository.SearchInvitationsAsync(new SearchInvitationsRequest { IncludeAllTenants = true, Limit = 0 }, RepositoryNow));
            Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => repository.SearchInvitationsAsync(new SearchInvitationsRequest { IncludeAllTenants = true, Offset = -1 }, RepositoryNow));
        }
    }

    private static UserInvitation CreateInvitation(
        string email,
        string tokenHash,
        Guid? tenantId = null,
        DateTimeOffset? expiresAt = null,
        DateTimeOffset? createdAt = null)
    {
        var created = createdAt ?? CreatedAt;
        return new UserInvitation
        {
            Id = Guid.NewGuid(),
            DisplayEmail = email,
            TenantId = tenantId,
            TokenHash = tokenHash,
            CreatedAt = created,
            ExpiresAt = expiresAt ?? created.AddDays(7),
            Version = Guid.NewGuid().ToString("N")
        };
    }

    private static AuditContext CreateAudit()
    {
        return new AuditContext(Guid.NewGuid(), "127.0.0.1");
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
