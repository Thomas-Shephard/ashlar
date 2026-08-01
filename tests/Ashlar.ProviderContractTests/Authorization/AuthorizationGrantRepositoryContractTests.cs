using Ashlar.Authorization.Models;
using System.Text.Json.Nodes;

namespace Ashlar.ProviderContractTests.Authorization;

/// <summary>Tests grant persistence, tenant isolation, lifecycle filtering, revocation, and rollback.</summary>
public abstract class AuthorizationGrantRepositoryContractTests : ProviderContractFixture
{
    private static readonly DateTimeOffset Now = new(2026, 6, 2, 12, 0, 0, TimeSpan.Zero);

    /// <summary>Verifies that grant lookup by ID recovers every stored authorization field.</summary>
    [Test]
    public async Task CreateAndGetGrantByIdMapsAllFields()
    {
        await using var scope = CreateAsyncScope();
        var tenantId = Guid.NewGuid();
        var user = await CreateUserAsync(GetUserRepository(scope.ServiceProvider), tenantId: tenantId);
        var repository = GetAuthorizationGrantRepository(scope.ServiceProvider);
        var grant = CreateGrant(
            user.Id,
            tenantId,
            "project",
            "alpha",
            permission: "projects.manage",
            expiresAt: Now.AddDays(7),
            metadata: """{"source":"contract","level":"high"}""");

        await repository.CreateGrantAsync(grant);

        var fetched = await repository.GetGrantAsync(grant.Id, grant.TenantId);

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

    /// <summary>Leaves unknown grant identifiers distinguishable from stored grants.</summary>
    [Test]
    public async Task MissingGrantReturnsNull()
    {
        await using var scope = CreateAsyncScope();
        var repository = GetAuthorizationGrantRepository(scope.ServiceProvider);

        Assert.That(await repository.GetGrantAsync(Guid.NewGuid(), null), Is.Null);
    }

    /// <summary>Verifies that ID lookup cannot reveal a grant from another tenant or global scope.</summary>
    [Test]
    public async Task TenantBoundedGetGrantMatchesOnlyRequestedTenantBoundary()
    {
        await using var scope = CreateAsyncScope();
        var tenantId = Guid.NewGuid();
        var otherTenantId = Guid.NewGuid();
        var tenantUser = await CreateUserAsync(GetUserRepository(scope.ServiceProvider), tenantId: tenantId);
        var globalUser = await CreateUserAsync(GetUserRepository(scope.ServiceProvider));
        var repository = GetAuthorizationGrantRepository(scope.ServiceProvider);
        var tenantGrant = CreateGrant(tenantUser.Id, tenantId, permission: "tenant.read");
        var globalGrant = CreateGrant(globalUser.Id, permission: "global.read");
        await repository.CreateGrantAsync(tenantGrant);
        await repository.CreateGrantAsync(globalGrant);

        var matchingTenant = await repository.GetGrantAsync(tenantGrant.Id, tenantId);
        var tenantAsGlobal = await repository.GetGrantAsync(tenantGrant.Id, null);
        var tenantAsOtherTenant = await repository.GetGrantAsync(tenantGrant.Id, otherTenantId);
        var matchingGlobal = await repository.GetGrantAsync(globalGrant.Id, null);
        var globalAsTenant = await repository.GetGrantAsync(globalGrant.Id, tenantId);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(matchingTenant?.Id, Is.EqualTo(tenantGrant.Id));
            Assert.That(tenantAsGlobal, Is.Null);
            Assert.That(tenantAsOtherTenant, Is.Null);
            Assert.That(matchingGlobal?.Id, Is.EqualTo(globalGrant.Id));
            Assert.That(globalAsTenant, Is.Null);
        }
    }

    /// <summary>Verifies that listing combines user, tenant, and resource scope without admitting near matches.</summary>
    [Test]
    public async Task ListGrantsFiltersByUserTenantAndScope()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var repository = GetAuthorizationGrantRepository(scope.ServiceProvider);
        var tenantId = Guid.NewGuid();
        var otherTenantId = Guid.NewGuid();
        var user = await CreateUserAsync(userRepository, tenantId: tenantId);
        var otherTenantUser = await CreateUserAsync(userRepository, tenantId: otherTenantId);
        var otherUser = await CreateUserAsync(userRepository, tenantId: tenantId);
        var matching = CreateGrant(user.Id, tenantId, "project", "alpha", permission: "matching");
        await repository.CreateGrantAsync(matching);
        await repository.CreateGrantAsync(CreateGrant(otherTenantUser.Id, otherTenantId, "project", "alpha", permission: "other-tenant"));
        await repository.CreateGrantAsync(CreateGrant(user.Id, tenantId, "project", "beta", permission: "other-scope"));
        await repository.CreateGrantAsync(CreateGrant(otherUser.Id, tenantId, "project", "alpha", permission: "other-user"));

        var grants = await repository.ListGrantsAsync(new ListAuthorizationGrantsRequest(user.Id, tenantId, "project", "alpha", ActiveOnly: true));

        Assert.That(grants.Select(grant => grant.Id), Is.EquivalentTo(new[] { matching.Id }));
    }

    /// <summary>Returns global and tenant grants only for their matching scope filters.</summary>
    [Test]
    public async Task ScopeFilteringHandlesGlobalAndScopedGrantsDistinctly()
    {
        await using var scope = CreateAsyncScope();
        var tenantId = Guid.NewGuid();
        var user = await CreateUserAsync(GetUserRepository(scope.ServiceProvider), tenantId: tenantId);
        var globalUser = await CreateUserAsync(GetUserRepository(scope.ServiceProvider));
        var repository = GetAuthorizationGrantRepository(scope.ServiceProvider);
        var scoped = CreateGrant(user.Id, tenantId, "project", "alpha", role: "reviewer");
        var global = CreateGrant(globalUser.Id, permission: "global.read");
        await repository.CreateGrantAsync(scoped);
        await repository.CreateGrantAsync(global);

        var exactGlobal = await repository.ListGrantsAsync(new ListAuthorizationGrantsRequest(globalUser.Id, ActiveOnly: true, ExactMatch: true));
        var globalBoundaryForTenantUser = await repository.ListGrantsAsync(new ListAuthorizationGrantsRequest(user.Id, ActiveOnly: true));
        var scopedResult = await repository.ListGrantsAsync(new ListAuthorizationGrantsRequest(user.Id, scoped.TenantId, scoped.ScopeType, scoped.ScopeId, ActiveOnly: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(exactGlobal.Select(grant => grant.Id), Is.EquivalentTo(new[] { global.Id }));
            Assert.That(globalBoundaryForTenantUser, Is.Empty);
            Assert.That(scopedResult.Select(grant => grant.Id), Is.EquivalentTo(new[] { scoped.Id }));
        }
    }

    /// <summary>Treats an absent tenant filter as a request for global grants only.</summary>
    [Test]
    public async Task NullTenantListReturnsOnlyGlobalGrants()
    {
        await using var scope = CreateAsyncScope();
        var tenantId = Guid.NewGuid();
        var tenantUser = await CreateUserAsync(GetUserRepository(scope.ServiceProvider), tenantId: tenantId);
        var globalUser = await CreateUserAsync(GetUserRepository(scope.ServiceProvider));
        var repository = GetAuthorizationGrantRepository(scope.ServiceProvider);
        var tenantGrant = CreateGrant(tenantUser.Id, tenantId, permission: "tenant.read");
        var globalGrant = CreateGrant(globalUser.Id, permission: "global.read");
        await repository.CreateGrantAsync(tenantGrant);
        await repository.CreateGrantAsync(globalGrant);

        var tenantUserGlobalBoundary = await repository.ListGrantsAsync(new ListAuthorizationGrantsRequest(tenantUser.Id, ActiveOnly: true));
        var globalUserGlobalBoundary = await repository.ListGrantsAsync(new ListAuthorizationGrantsRequest(globalUser.Id, ActiveOnly: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(tenantUserGlobalBoundary, Is.Empty);
            Assert.That(globalUserGlobalBoundary.Select(grant => grant.Id), Is.EquivalentTo(new[] { globalGrant.Id }));
        }
    }

    /// <summary>Excludes global and unrelated tenant grants from a tenant-specific listing.</summary>
    [Test]
    public async Task TenantListReturnsOnlyRequestedTenantGrants()
    {
        await using var scope = CreateAsyncScope();
        var tenantId = Guid.NewGuid();
        var otherTenantId = Guid.NewGuid();
        var tenantUser = await CreateUserAsync(GetUserRepository(scope.ServiceProvider), tenantId: tenantId);
        var otherTenantUser = await CreateUserAsync(GetUserRepository(scope.ServiceProvider), tenantId: otherTenantId);
        var globalUser = await CreateUserAsync(GetUserRepository(scope.ServiceProvider));
        var repository = GetAuthorizationGrantRepository(scope.ServiceProvider);
        var matching = CreateGrant(tenantUser.Id, tenantId, permission: "tenant.read");
        await repository.CreateGrantAsync(matching);
        await repository.CreateGrantAsync(CreateGrant(otherTenantUser.Id, otherTenantId, permission: "other.read"));
        await repository.CreateGrantAsync(CreateGrant(globalUser.Id, permission: "global.read"));

        var grants = await repository.ListGrantsAsync(new ListAuthorizationGrantsRequest(tenantUser.Id, tenantId, ActiveOnly: true));

        Assert.That(grants.Select(grant => grant.Id), Is.EquivalentTo(new[] { matching.Id }));
    }

    /// <summary>Confines broad permission matching to the requested tenant boundary.</summary>
    [Test]
    public async Task BroadScopeMatchingDoesNotBroadenTenantBoundary()
    {
        await using var scope = CreateAsyncScope();
        var tenantId = Guid.NewGuid();
        var otherTenantId = Guid.NewGuid();
        var tenantUser = await CreateUserAsync(GetUserRepository(scope.ServiceProvider), tenantId: tenantId);
        var otherTenantUser = await CreateUserAsync(GetUserRepository(scope.ServiceProvider), tenantId: otherTenantId);
        var repository = GetAuthorizationGrantRepository(scope.ServiceProvider);
        var broadTenantGrant = CreateGrant(tenantUser.Id, tenantId, permission: "tenant.broad");
        var scopedTenantGrant = CreateGrant(tenantUser.Id, tenantId, "project", "alpha", permission: "tenant.scoped");
        await repository.CreateGrantAsync(broadTenantGrant);
        await repository.CreateGrantAsync(scopedTenantGrant);
        await repository.CreateGrantAsync(CreateGrant(otherTenantUser.Id, otherTenantId, permission: "other.broad"));

        var broadScope = await repository.ListGrantsAsync(new ListAuthorizationGrantsRequest(tenantUser.Id, tenantId, "project", "alpha", ActiveOnly: true));
        var exactScope = await repository.ListGrantsAsync(new ListAuthorizationGrantsRequest(tenantUser.Id, tenantId, "project", "alpha", ActiveOnly: true, ExactMatch: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(broadScope.Select(grant => grant.Id), Is.EquivalentTo(new[] { broadTenantGrant.Id, scopedTenantGrant.Id }));
            Assert.That(exactScope.Select(grant => grant.Id), Is.EquivalentTo(new[] { scopedTenantGrant.Id }));
        }
    }

    /// <summary>Treats an invalid permission pattern as an empty match rather than broad access.</summary>
    [Test]
    public async Task MalformedScopeFilterReturnsNoGrants()
    {
        await using var scope = CreateAsyncScope();
        var tenantId = Guid.NewGuid();
        var user = await CreateUserAsync(GetUserRepository(scope.ServiceProvider), tenantId: tenantId);
        var repository = GetAuthorizationGrantRepository(scope.ServiceProvider);
        var tenantWideGrant = CreateGrant(user.Id, tenantId, permission: "tenant.broad");
        await repository.CreateGrantAsync(tenantWideGrant);

        var missingScopeId = await repository.ListGrantsAsync(new ListAuthorizationGrantsRequest(user.Id, tenantId, ScopeType: "project", ActiveOnly: true));
        var missingScopeType = await repository.ListGrantsAsync(new ListAuthorizationGrantsRequest(user.Id, tenantId, ScopeId: "alpha", ActiveOnly: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missingScopeId, Is.Empty);
            Assert.That(missingScopeType, Is.Empty);
        }
    }

    /// <summary>Verifies that a grant cannot assign a tenant user to another tenant.</summary>
    [Test]
    public async Task CreateGrantRejectsTenantUserWithDifferentTenant()
    {
        await using var scope = CreateAsyncScope();
        var user = await CreateUserAsync(GetUserRepository(scope.ServiceProvider), tenantId: Guid.NewGuid());
        var repository = GetAuthorizationGrantRepository(scope.ServiceProvider);

        Assert.That(async () => await repository.CreateGrantAsync(CreateGrant(user.Id, Guid.NewGuid(), permission: "read")), Throws.Exception);
    }

    /// <summary>Verifies that a tenant user cannot receive a global grant.</summary>
    [Test]
    public async Task CreateGrantRejectsTenantUserWithNullTenant()
    {
        await using var scope = CreateAsyncScope();
        var user = await CreateUserAsync(GetUserRepository(scope.ServiceProvider), tenantId: Guid.NewGuid());
        var repository = GetAuthorizationGrantRepository(scope.ServiceProvider);

        Assert.That(async () => await repository.CreateGrantAsync(CreateGrant(user.Id, permission: "read")), Throws.Exception);
    }

    /// <summary>Verifies that a global user cannot receive a tenant grant.</summary>
    [Test]
    public async Task CreateGrantRejectsGlobalUserWithTenant()
    {
        await using var scope = CreateAsyncScope();
        var user = await CreateUserAsync(GetUserRepository(scope.ServiceProvider));
        var repository = GetAuthorizationGrantRepository(scope.ServiceProvider);

        Assert.That(async () => await repository.CreateGrantAsync(CreateGrant(user.Id, Guid.NewGuid(), permission: "read")), Throws.Exception);
    }

    /// <summary>Verifies that valid tenant and global grants remain independently retrievable.</summary>
    [Test]
    public async Task CreateGrantPersistsMatchingTenantAndGlobalRows()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var repository = GetAuthorizationGrantRepository(scope.ServiceProvider);
        var tenantId = Guid.NewGuid();
        var tenantUser = await CreateUserAsync(userRepository, tenantId: tenantId);
        var globalUser = await CreateUserAsync(userRepository);
        var tenantGrant = CreateGrant(tenantUser.Id, tenantId, permission: "tenant.read");
        var globalGrant = CreateGrant(globalUser.Id, permission: "global.read");

        await repository.CreateGrantAsync(tenantGrant);
        await repository.CreateGrantAsync(globalGrant);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(await repository.GetGrantAsync(tenantGrant.Id, tenantGrant.TenantId), Is.Not.Null);
            Assert.That(await repository.GetGrantAsync(globalGrant.Id, globalGrant.TenantId), Is.Not.Null);
        }
    }

    /// <summary>Preserves the distinct role and permission payloads of stored grants.</summary>
    [Test]
    public async Task RoleGrantsAndPermissionGrantsBothRoundTrip()
    {
        await using var scope = CreateAsyncScope();
        var user = await CreateUserAsync(GetUserRepository(scope.ServiceProvider));
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

    /// <summary>Limits active listings to usable grants while retaining terminal grants in full history.</summary>
    [Test]
    public async Task ActiveOnlyListingExcludesRevokedAndExpiredButAllListingIncludesThem()
    {
        await using var scope = CreateAsyncScope();
        var user = await CreateUserAsync(GetUserRepository(scope.ServiceProvider));
        var repository = GetAuthorizationGrantRepository(scope.ServiceProvider);
        var active = CreateGrant(user.Id, permission: "active");
        var revoked = CreateGrant(user.Id, permission: "revoked");
        var expired = CreateGrant(user.Id, permission: "expired", expiresAt: new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        await repository.CreateGrantAsync(active);
        await repository.CreateGrantAsync(revoked);
        await repository.CreateGrantAsync(expired);
        await repository.RevokeGrantAsync(revoked.Id, revoked.TenantId, Now.AddMinutes(1));

        var activeOnly = await repository.ListGrantsAsync(new ListAuthorizationGrantsRequest(user.Id, ActiveOnly: true));
        var all = await repository.ListGrantsAsync(new ListAuthorizationGrantsRequest(user.Id, ActiveOnly: false));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(activeOnly.Select(grant => grant.Id), Is.EquivalentTo(new[] { active.Id }));
            Assert.That(all.Select(grant => grant.Id), Is.EquivalentTo(new[] { active.Id, revoked.Id, expired.Id }));
        }
    }

    /// <summary>Verifies that revocation succeeds once and preserves its original timestamp.</summary>
    [Test]
    public async Task RevokeGrantSucceedsOncePersistsTimestampAndPreservesFirstRevocation()
    {
        await using var scope = CreateAsyncScope();
        var tenantId = Guid.NewGuid();
        var user = await CreateUserAsync(GetUserRepository(scope.ServiceProvider), tenantId: tenantId);
        var repository = GetAuthorizationGrantRepository(scope.ServiceProvider);
        var grant = CreateGrant(user.Id, tenantId, permission: "revoke");
        var firstRevokedAt = Now.AddMinutes(1);
        var secondRevokedAt = Now.AddMinutes(2);
        await repository.CreateGrantAsync(grant);

        var first = await repository.RevokeGrantAsync(grant.Id, grant.TenantId, firstRevokedAt);
        var second = await repository.RevokeGrantAsync(grant.Id, grant.TenantId, secondRevokedAt);
        var fetched = await repository.GetGrantAsync(grant.Id, grant.TenantId);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(first, Is.True);
            Assert.That(second, Is.False);
            Assert.That(fetched!.RevokedAt, Is.EqualTo(firstRevokedAt));
        }
    }

    /// <summary>Verifies that only a global revocation request can match a global grant.</summary>
    [Test]
    public async Task RevokeGrantMatchesGlobalGrantOnlyWithNullTenant()
    {
        await using var scope = CreateAsyncScope();
        var user = await CreateUserAsync(GetUserRepository(scope.ServiceProvider));
        var repository = GetAuthorizationGrantRepository(scope.ServiceProvider);
        var global = CreateGrant(user.Id, permission: "global.revoke");
        var requestedTenantId = Guid.NewGuid();
        var revokedAt = Now.AddMinutes(2);
        await repository.CreateGrantAsync(global);

        var wrongTenant = await repository.RevokeGrantAsync(global.Id, requestedTenantId, Now.AddMinutes(1));
        var nullTenant = await repository.RevokeGrantAsync(global.Id, null, revokedAt);
        var fetched = await repository.GetGrantAsync(global.Id, global.TenantId);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(wrongTenant, Is.False);
            Assert.That(nullTenant, Is.True);
            Assert.That(fetched!.RevokedAt, Is.EqualTo(revokedAt));
        }
    }

    /// <summary>Verifies that revocation cannot affect the same grant ID through another tenant.</summary>
    [Test]
    public async Task RevokeGrantDoesNotCrossTenantBoundary()
    {
        await using var scope = CreateAsyncScope();
        var tenantId = Guid.NewGuid();
        var user = await CreateUserAsync(GetUserRepository(scope.ServiceProvider), tenantId: tenantId);
        var repository = GetAuthorizationGrantRepository(scope.ServiceProvider);
        var grant = CreateGrant(user.Id, tenantId, permission: "tenant.revoke");
        await repository.CreateGrantAsync(grant);

        var wrongTenant = await repository.RevokeGrantAsync(grant.Id, Guid.NewGuid(), Now.AddMinutes(1));
        var nullTenant = await repository.RevokeGrantAsync(grant.Id, null, Now.AddMinutes(2));
        var fetched = await repository.GetGrantAsync(grant.Id, grant.TenantId);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(wrongTenant, Is.False);
            Assert.That(nullTenant, Is.False);
            Assert.That(fetched!.RevokedAt, Is.Null);
        }
    }

    /// <summary>Verifies that a tenant-scoped revocation updates its matching grant.</summary>
    [Test]
    public async Task RevokeGrantMatchesTenantScopedGrant()
    {
        await using var scope = CreateAsyncScope();
        var tenantId = Guid.NewGuid();
        var user = await CreateUserAsync(GetUserRepository(scope.ServiceProvider), tenantId: tenantId);
        var repository = GetAuthorizationGrantRepository(scope.ServiceProvider);
        var grant = CreateGrant(user.Id, tenantId, permission: "tenant.revoke");
        var revokedAt = Now.AddMinutes(1);
        await repository.CreateGrantAsync(grant);

        var revoked = await repository.RevokeGrantAsync(grant.Id, grant.TenantId, revokedAt);
        var fetched = await repository.GetGrantAsync(grant.Id, grant.TenantId);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(revoked, Is.True);
            Assert.That(fetched!.RevokedAt, Is.EqualTo(revokedAt));
        }
    }

    /// <summary>Verifies that revoking an absent grant reports no change.</summary>
    [Test]
    public async Task RevokeMissingGrantReturnsFalse()
    {
        await using var scope = CreateAsyncScope();
        var repository = GetAuthorizationGrantRepository(scope.ServiceProvider);

        Assert.That(await repository.RevokeGrantAsync(Guid.NewGuid(), Guid.NewGuid(), Now), Is.False);
    }

    /// <summary>Leaves no persisted grant after its surrounding transaction is rolled back.</summary>
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

            var user = await CreateUserAsync(GetUserRepository(scope.ServiceProvider));
            var repository = GetAuthorizationGrantRepository(scope.ServiceProvider);
            var grant = CreateGrant(user.Id, permission: "rollback");
            grantId = grant.Id;

            await using var transaction = await transactionProvider.BeginTransactionAsync();
            await repository.CreateGrantAsync(grant);
            await transaction.RollbackAsync();
        }

        await using var verificationScope = CreateAsyncScope();
        var verificationRepository = GetAuthorizationGrantRepository(verificationScope.ServiceProvider);
        Assert.That(await verificationRepository.GetGrantAsync(grantId, null), Is.Null);
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
