using Ashlar.Identity.Models;
using System.Text.Json.Nodes;

namespace Ashlar.ProviderContractTests.Identity;

internal abstract class InvitationRepositoryContractTests : ProviderContractFixture
{
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
            Assert.That(fetched.Email, Is.EqualTo(invitation.Email));
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
        Assert.That(await repository.RevokeInvitationsByEmailAsync(invitation.Email), Is.EqualTo(1));

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
            createdAt: DateTimeOffset.UtcNow.AddDays(-2),
            expiresAt: DateTimeOffset.UtcNow.AddDays(-1));
        await repository.CreateInvitationAsync(invitation);

        invitation.AcceptedAt = DateTimeOffset.UtcNow;
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
            Email = email,
            TenantId = tenantId,
            TokenHash = tokenHash,
            CreatedAt = created,
            ExpiresAt = expiresAt ?? created.AddDays(7),
            Version = Guid.NewGuid().ToString("N")
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
