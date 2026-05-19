using Ashlar.Authorization.Models;
using System.Text.Json.Nodes;

namespace Ashlar.ProviderContractTests.Authorization;

internal abstract class AuthorizationGrantRepositoryContractTests : ProviderContractFixture
{
    private static readonly DateTimeOffset Now = new(2026, 6, 2, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task CreateAndGetGrantByIdMapsAllFields()
    {
        await using var scope = CreateAsyncScope();
        var user = await CreateUserAsync(GetIdentityRepository(scope.ServiceProvider));
        var repository = GetAuthorizationGrantRepository(scope.ServiceProvider);
        var tenantId = Guid.NewGuid();
        var grant = CreateGrant(
            user.Id,
            tenantId,
            "project",
            "alpha",
            permission: "projects.manage",
            expiresAt: Now.AddDays(7),
            metadata: """{"source":"contract","level":"high"}""");

        await repository.CreateGrantAsync(grant);

        var fetched = await repository.GetGrantAsync(grant.Id);

        Assert.That(fetched, Is.Not.Null);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched!.Id, Is.EqualTo(grant.Id));
            Assert.That(fetched.UserId, Is.EqualTo(grant.UserId));
            Assert.That(fetched.TenantId, Is.EqualTo(grant.TenantId));
            Assert.That(fetched.ScopeType, Is.EqualTo(grant.ScopeType));
            Assert.That(fetched.ScopeId, Is.EqualTo(grant.ScopeId));
            Assert.That(fetched.Role, Is.EqualTo(grant.Role));
            Assert.That(fetched.Permission, Is.EqualTo(grant.Permission));
            Assert.That(fetched.CreatedAt, Is.EqualTo(grant.CreatedAt));
            Assert.That(fetched.ExpiresAt, Is.EqualTo(grant.ExpiresAt));
            Assert.That(fetched.RevokedAt, Is.Null);
            Assert.That(JsonEquals(fetched.Metadata, grant.Metadata), Is.True);
        }
    }

    [Test]
    public async Task MissingGrantReturnsNull()
    {
        await using var scope = CreateAsyncScope();
        var repository = GetAuthorizationGrantRepository(scope.ServiceProvider);

        Assert.That(await repository.GetGrantAsync(Guid.NewGuid()), Is.Null);
    }

    [Test]
    public async Task ListGrantsFiltersByUserTenantAndScope()
    {
        await using var scope = CreateAsyncScope();
        var identityRepository = GetIdentityRepository(scope.ServiceProvider);
        var repository = GetAuthorizationGrantRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(identityRepository);
        var otherUser = await CreateUserAsync(identityRepository);
        var tenantId = Guid.NewGuid();
        var otherTenantId = Guid.NewGuid();
        var matching = CreateGrant(user.Id, tenantId, "project", "alpha", permission: "matching");
        await repository.CreateGrantAsync(matching);
        await repository.CreateGrantAsync(CreateGrant(user.Id, otherTenantId, "project", "alpha", permission: "other-tenant"));
        await repository.CreateGrantAsync(CreateGrant(user.Id, tenantId, "project", "beta", permission: "other-scope"));
        await repository.CreateGrantAsync(CreateGrant(otherUser.Id, tenantId, "project", "alpha", permission: "other-user"));

        var grants = await repository.ListGrantsAsync(new ListAuthorizationGrantsRequest(user.Id, tenantId, "project", "alpha", ActiveOnly: true));

        Assert.That(grants.Select(grant => grant.Id), Is.EquivalentTo(new[] { matching.Id }));
    }

    [Test]
    public async Task ScopeFilteringHandlesGlobalAndScopedGrantsDistinctly()
    {
        await using var scope = CreateAsyncScope();
        var user = await CreateUserAsync(GetIdentityRepository(scope.ServiceProvider));
        var repository = GetAuthorizationGrantRepository(scope.ServiceProvider);
        var scoped = CreateGrant(user.Id, Guid.NewGuid(), "project", "alpha", role: "reviewer");
        var global = CreateGrant(user.Id, permission: "global.read");
        await repository.CreateGrantAsync(scoped);
        await repository.CreateGrantAsync(global);

        var exactGlobal = await repository.ListGrantsAsync(new ListAuthorizationGrantsRequest(user.Id, ActiveOnly: true, ExactMatch: true));
        var broad = await repository.ListGrantsAsync(new ListAuthorizationGrantsRequest(user.Id, ActiveOnly: true));
        var scopedResult = await repository.ListGrantsAsync(new ListAuthorizationGrantsRequest(user.Id, scoped.TenantId, scoped.ScopeType, scoped.ScopeId, ActiveOnly: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(exactGlobal.Select(grant => grant.Id), Is.EquivalentTo(new[] { global.Id }));
            Assert.That(broad.Select(grant => grant.Id), Is.EquivalentTo(new[] { global.Id, scoped.Id }));
            Assert.That(scopedResult.Select(grant => grant.Id), Is.EquivalentTo(new[] { scoped.Id }));
        }
    }

    [Test]
    public async Task RoleGrantsAndPermissionGrantsBothRoundTrip()
    {
        await using var scope = CreateAsyncScope();
        var user = await CreateUserAsync(GetIdentityRepository(scope.ServiceProvider));
        var repository = GetAuthorizationGrantRepository(scope.ServiceProvider);
        var roleGrant = CreateGrant(user.Id, role: "admin");
        var permissionGrant = CreateGrant(user.Id, permission: "reports.read");
        await repository.CreateGrantAsync(roleGrant);
        await repository.CreateGrantAsync(permissionGrant);

        var grants = await repository.ListGrantsAsync(new ListAuthorizationGrantsRequest(user.Id, ActiveOnly: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(grants.Single(grant => grant.Id == roleGrant.Id).Role, Is.EqualTo("admin"));
            Assert.That(grants.Single(grant => grant.Id == roleGrant.Id).Permission, Is.Null);
            Assert.That(grants.Single(grant => grant.Id == permissionGrant.Id).Permission, Is.EqualTo("reports.read"));
            Assert.That(grants.Single(grant => grant.Id == permissionGrant.Id).Role, Is.Null);
        }
    }

    [Test]
    public async Task ActiveOnlyListingExcludesRevokedAndExpiredButAllListingIncludesThem()
    {
        await using var scope = CreateAsyncScope();
        var user = await CreateUserAsync(GetIdentityRepository(scope.ServiceProvider));
        var repository = GetAuthorizationGrantRepository(scope.ServiceProvider);
        var active = CreateGrant(user.Id, permission: "active");
        var revoked = CreateGrant(user.Id, permission: "revoked");
        var expired = CreateGrant(user.Id, permission: "expired", expiresAt: new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        await repository.CreateGrantAsync(active);
        await repository.CreateGrantAsync(revoked);
        await repository.CreateGrantAsync(expired);
        await repository.RevokeGrantAsync(revoked.Id, Now.AddMinutes(1));

        var activeOnly = await repository.ListGrantsAsync(new ListAuthorizationGrantsRequest(user.Id, ActiveOnly: true));
        var all = await repository.ListGrantsAsync(new ListAuthorizationGrantsRequest(user.Id, ActiveOnly: false));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(activeOnly.Select(grant => grant.Id), Is.EquivalentTo(new[] { active.Id }));
            Assert.That(all.Select(grant => grant.Id), Is.EquivalentTo(new[] { active.Id, revoked.Id, expired.Id }));
        }
    }

    [Test]
    public async Task RevokeGrantSucceedsOncePersistsTimestampAndPreservesFirstRevocation()
    {
        await using var scope = CreateAsyncScope();
        var user = await CreateUserAsync(GetIdentityRepository(scope.ServiceProvider));
        var repository = GetAuthorizationGrantRepository(scope.ServiceProvider);
        var grant = CreateGrant(user.Id, permission: "revoke");
        var firstRevokedAt = Now.AddMinutes(1);
        var secondRevokedAt = Now.AddMinutes(2);
        await repository.CreateGrantAsync(grant);

        var first = await repository.RevokeGrantAsync(grant.Id, firstRevokedAt);
        var second = await repository.RevokeGrantAsync(grant.Id, secondRevokedAt);
        var fetched = await repository.GetGrantAsync(grant.Id);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(first, Is.True);
            Assert.That(second, Is.False);
            Assert.That(fetched!.RevokedAt, Is.EqualTo(firstRevokedAt));
        }
    }

    [Test]
    public async Task RevokeMissingGrantReturnsFalse()
    {
        await using var scope = CreateAsyncScope();
        var repository = GetAuthorizationGrantRepository(scope.ServiceProvider);

        Assert.That(await repository.RevokeGrantAsync(Guid.NewGuid(), Now), Is.False);
    }

    [Test]
    public async Task GrantWritesRollBackWhenProviderSupportsTransactions()
    {
        Guid grantId;
        await using (var scope = CreateAsyncScope())
        {
            var transactionProvider = GetTransactionProvider(scope.ServiceProvider);
            if (transactionProvider == null)
            {
                Assert.Ignore("Provider does not register IAshlarTransactionProvider.");
            }

            var user = await CreateUserAsync(GetIdentityRepository(scope.ServiceProvider));
            var repository = GetAuthorizationGrantRepository(scope.ServiceProvider);
            var grant = CreateGrant(user.Id, permission: "rollback");
            grantId = grant.Id;

            await using var transaction = await transactionProvider.BeginTransactionAsync();
            await repository.CreateGrantAsync(grant);
            await transaction.RollbackAsync();
        }

        await using var verificationScope = CreateAsyncScope();
        var verificationRepository = GetAuthorizationGrantRepository(verificationScope.ServiceProvider);
        Assert.That(await verificationRepository.GetGrantAsync(grantId), Is.Null);
    }

    private static AuthorizationGrant CreateGrant(
        Guid userId,
        Guid? tenantId = null,
        string? scopeType = null,
        string? scopeId = null,
        string? role = null,
        string? permission = null,
        DateTimeOffset? expiresAt = null,
        string? metadata = null)
    {
        return new AuthorizationGrant
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            TenantId = tenantId,
            ScopeType = scopeType,
            ScopeId = scopeId,
            Role = role,
            Permission = permission,
            CreatedAt = Now,
            ExpiresAt = expiresAt,
            Metadata = metadata
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
