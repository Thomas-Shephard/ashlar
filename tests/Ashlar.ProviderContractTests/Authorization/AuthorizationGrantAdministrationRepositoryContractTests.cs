using Ashlar.Authorization.Models;

namespace Ashlar.ProviderContractTests.Authorization;

internal abstract class AuthorizationGrantAdministrationRepositoryContractTests : ProviderContractFixture
{
    private static readonly DateTimeOffset Now = new(2026, 6, 2, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task SearchAuthorizationGrantsAsyncFiltersTenantGlobalAndAllTenantScopes()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var repository = GetAuthorizationGrantRepository(scope.ServiceProvider);
        var adminRepository = GetAuthorizationGrantAdministrationRepository(scope.ServiceProvider);
        var tenantId = Guid.NewGuid();
        var otherTenantId = Guid.NewGuid();
        var tenantUser = await CreateUserAsync(userRepository, tenantId: tenantId);
        var otherTenantUser = await CreateUserAsync(userRepository, tenantId: otherTenantId);
        var globalUser = await CreateUserAsync(userRepository);
        var tenantGrant = CreateGrant(tenantUser.Id, tenantId, permission: "tenant.read");
        var otherTenantGrant = CreateGrant(otherTenantUser.Id, otherTenantId, permission: "other.read");
        var globalGrant = CreateGrant(globalUser.Id, permission: "global.read");
        await repository.CreateGrantAsync(tenantGrant);
        await repository.CreateGrantAsync(otherTenantGrant);
        await repository.CreateGrantAsync(globalGrant);

        var tenant = await adminRepository.SearchAuthorizationGrantsAsync(new SearchAuthorizationGrantsRequest { Tenant = new TenantContext(tenantId) }, Now);
        var global = await adminRepository.SearchAuthorizationGrantsAsync(new SearchAuthorizationGrantsRequest { Tenant = TenantContext.Global }, Now);
        var all = await adminRepository.SearchAuthorizationGrantsAsync(new SearchAuthorizationGrantsRequest { IncludeAllTenants = true }, Now);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(tenant.Select(grant => grant.Id), Is.EquivalentTo(new[] { tenantGrant.Id }));
            Assert.That(global.Select(grant => grant.Id), Is.EquivalentTo(new[] { globalGrant.Id }));
            Assert.That(all.Select(grant => grant.Id), Is.EquivalentTo(new[] { tenantGrant.Id, otherTenantGrant.Id, globalGrant.Id }));
        }
    }

    [Test]
    public async Task SearchAuthorizationGrantsAsyncRequiresExplicitTenantScope()
    {
        await using var scope = CreateAsyncScope();
        var adminRepository = GetAuthorizationGrantAdministrationRepository(scope.ServiceProvider);

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentException>(() => adminRepository.SearchAuthorizationGrantsAsync(new SearchAuthorizationGrantsRequest(), Now));
            Assert.ThrowsAsync<ArgumentException>(() => adminRepository.SearchAuthorizationGrantsAsync(
                new SearchAuthorizationGrantsRequest { Tenant = TenantContext.Global, IncludeAllTenants = true },
                Now));
        }
    }

    [Test]
    public async Task SearchAuthorizationGrantsAsyncAppliesValueFilters()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var repository = GetAuthorizationGrantRepository(scope.ServiceProvider);
        var adminRepository = GetAuthorizationGrantAdministrationRepository(scope.ServiceProvider);
        var tenantId = Guid.NewGuid();
        var user = await CreateUserAsync(userRepository, tenantId: tenantId);
        var otherUser = await CreateUserAsync(userRepository, tenantId: tenantId);
        var matching = CreateGrant(user.Id, tenantId, "project", "alpha", role: "reviewer");
        await repository.CreateGrantAsync(matching);
        await repository.CreateGrantAsync(CreateGrant(otherUser.Id, tenantId, "project", "alpha", role: "reviewer"));
        await repository.CreateGrantAsync(CreateGrant(user.Id, tenantId, "project", "beta", permission: "projects.read"));

        var byUser = await adminRepository.SearchAuthorizationGrantsAsync(new SearchAuthorizationGrantsRequest { Tenant = new TenantContext(tenantId), UserId = user.Id }, Now);
        var byRole = await adminRepository.SearchAuthorizationGrantsAsync(new SearchAuthorizationGrantsRequest { Tenant = new TenantContext(tenantId), Role = "reviewer" }, Now);
        var byPermission = await adminRepository.SearchAuthorizationGrantsAsync(new SearchAuthorizationGrantsRequest { Tenant = new TenantContext(tenantId), Permission = "projects.read" }, Now);
        var byScope = await adminRepository.SearchAuthorizationGrantsAsync(new SearchAuthorizationGrantsRequest { Tenant = new TenantContext(tenantId), ScopeType = "project", ScopeId = "alpha" }, Now);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(byUser.Select(grant => grant.UserId), Is.All.EqualTo(user.Id));
            Assert.That(byRole.Select(grant => grant.Id), Does.Contain(matching.Id));
            Assert.That(byPermission, Has.Count.EqualTo(1));
            Assert.That(byPermission.Single().Permission, Is.EqualTo("projects.read"));
            Assert.That(byScope.Select(grant => grant.Id), Is.EquivalentTo(new[] { matching.Id, byRole.Single(grant => grant.UserId == otherUser.Id).Id }));
        }
    }

    [Test]
    public async Task SearchAuthorizationGrantsAsyncFiltersStatusAndTimeWindows()
    {
        await using var scope = CreateAsyncScope();
        var user = await CreateUserAsync(GetUserRepository(scope.ServiceProvider));
        var repository = GetAuthorizationGrantRepository(scope.ServiceProvider);
        var adminRepository = GetAuthorizationGrantAdministrationRepository(scope.ServiceProvider);
        var active = CreateGrant(user.Id, permission: "active", createdAt: Now.AddMinutes(-30), expiresAt: Now.AddDays(1));
        var expired = CreateGrant(user.Id, permission: "expired", createdAt: Now.AddMinutes(-20), expiresAt: Now.AddMinutes(-1));
        var revoked = CreateGrant(user.Id, permission: "revoked", createdAt: Now.AddMinutes(-10), expiresAt: Now.AddDays(2));
        var revokedAt = Now.AddMinutes(-5);
        await repository.CreateGrantAsync(active);
        await repository.CreateGrantAsync(expired);
        await repository.CreateGrantAsync(revoked);
        await repository.RevokeGrantAsync(revoked.Id, null, revokedAt);

        var activeResult = await adminRepository.SearchAuthorizationGrantsAsync(new SearchAuthorizationGrantsRequest { Tenant = TenantContext.Global, Status = AuthorizationGrantAdministrationStatus.Active }, Now);
        var expiredResult = await adminRepository.SearchAuthorizationGrantsAsync(new SearchAuthorizationGrantsRequest { Tenant = TenantContext.Global, Status = AuthorizationGrantAdministrationStatus.Expired }, Now);
        var revokedResult = await adminRepository.SearchAuthorizationGrantsAsync(new SearchAuthorizationGrantsRequest { Tenant = TenantContext.Global, Status = AuthorizationGrantAdministrationStatus.Revoked }, Now);
        var createdWindow = await adminRepository.SearchAuthorizationGrantsAsync(new SearchAuthorizationGrantsRequest { Tenant = TenantContext.Global, CreatedFrom = Now.AddMinutes(-25), CreatedTo = Now.AddMinutes(-15) }, Now);
        var expiresWindow = await adminRepository.SearchAuthorizationGrantsAsync(new SearchAuthorizationGrantsRequest { Tenant = TenantContext.Global, ExpiresFrom = Now.AddDays(1).AddMinutes(-1), ExpiresTo = Now.AddDays(1).AddMinutes(1) }, Now);
        var revokedWindow = await adminRepository.SearchAuthorizationGrantsAsync(new SearchAuthorizationGrantsRequest { Tenant = TenantContext.Global, RevokedFrom = revokedAt.AddMinutes(-1), RevokedTo = revokedAt.AddMinutes(1) }, Now);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(activeResult.Single().Id, Is.EqualTo(active.Id));
            Assert.That(activeResult.Single().Status, Is.EqualTo(AuthorizationGrantAdministrationStatus.Active));
            Assert.That(expiredResult.Single().Id, Is.EqualTo(expired.Id));
            Assert.That(expiredResult.Single().Status, Is.EqualTo(AuthorizationGrantAdministrationStatus.Expired));
            Assert.That(revokedResult.Single().Id, Is.EqualTo(revoked.Id));
            Assert.That(revokedResult.Single().Status, Is.EqualTo(AuthorizationGrantAdministrationStatus.Revoked));
            Assert.That(createdWindow.Single().Id, Is.EqualTo(expired.Id));
            Assert.That(expiresWindow.Single().Id, Is.EqualTo(active.Id));
            Assert.That(revokedWindow.Single().Id, Is.EqualTo(revoked.Id));
        }
    }

    [Test]
    public async Task SearchAuthorizationGrantsAsyncAppliesPagingAndStableOrdering()
    {
        await using var scope = CreateAsyncScope();
        var user = await CreateUserAsync(GetUserRepository(scope.ServiceProvider));
        var repository = GetAuthorizationGrantRepository(scope.ServiceProvider);
        var adminRepository = GetAuthorizationGrantAdministrationRepository(scope.ServiceProvider);
        var older = CreateGrant(user.Id, permission: "older", createdAt: Now.AddMinutes(-3));
        var middle = CreateGrant(user.Id, permission: "middle", createdAt: Now.AddMinutes(-2));
        var newer = CreateGrant(user.Id, permission: "newer", createdAt: Now.AddMinutes(-1));
        await repository.CreateGrantAsync(older);
        await repository.CreateGrantAsync(middle);
        await repository.CreateGrantAsync(newer);

        var page = await adminRepository.SearchAuthorizationGrantsAsync(new SearchAuthorizationGrantsRequest { Tenant = TenantContext.Global, Limit = 1, Offset = 1 }, Now);

        Assert.That(page.Select(grant => grant.Id), Is.EqualTo(new[] { middle.Id }));
    }

    [Test]
    public async Task GetAuthorizationGrantAsyncReturnsSafeProjectionAndHonorsTenantScope()
    {
        await using var scope = CreateAsyncScope();
        var tenantId = Guid.NewGuid();
        var user = await CreateUserAsync(GetUserRepository(scope.ServiceProvider), tenantId: tenantId);
        var repository = GetAuthorizationGrantRepository(scope.ServiceProvider);
        var adminRepository = GetAuthorizationGrantAdministrationRepository(scope.ServiceProvider);
        var grant = CreateGrant(user.Id, tenantId, "project", "alpha", permission: "projects.manage", metadata: """{"secret":"do-not-project"}""");
        await repository.CreateGrantAsync(grant);

        var lookup = await adminRepository.GetAuthorizationGrantAsync(new AuthorizationGrantAdministrationLookupRequest(grant.Id, new TenantContext(tenantId)), Now);
        var allTenantLookup = await adminRepository.GetAuthorizationGrantAsync(new AuthorizationGrantAdministrationLookupRequest(grant.Id, IncludeAllTenants: true), Now);
        var mismatch = await adminRepository.GetAuthorizationGrantAsync(new AuthorizationGrantAdministrationLookupRequest(grant.Id, new TenantContext(Guid.NewGuid())), Now);
        var missing = await adminRepository.GetAuthorizationGrantAsync(new AuthorizationGrantAdministrationLookupRequest(Guid.NewGuid(), new TenantContext(tenantId)), Now);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(lookup, Is.Not.Null);
            Assert.That(lookup!.Id, Is.EqualTo(grant.Id));
            Assert.That(lookup.Permission, Is.EqualTo("projects.manage"));
            Assert.That(lookup.TenantId, Is.EqualTo(tenantId));
            Assert.That(allTenantLookup, Is.Not.Null);
            Assert.That(mismatch, Is.Null);
            Assert.That(missing, Is.Null);
        }
    }

    [Test]
    public async Task GetAuthorizationGrantAsyncRequiresExplicitTenantScope()
    {
        await using var scope = CreateAsyncScope();
        var adminRepository = GetAuthorizationGrantAdministrationRepository(scope.ServiceProvider);
        var grantId = Guid.NewGuid();

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentException>(() => adminRepository.GetAuthorizationGrantAsync(new AuthorizationGrantAdministrationLookupRequest(grantId), Now));
            Assert.ThrowsAsync<ArgumentException>(() => adminRepository.GetAuthorizationGrantAsync(
                new AuthorizationGrantAdministrationLookupRequest(grantId, TenantContext.Global, IncludeAllTenants: true),
                Now));
        }
    }

    private static AuthorizationGrant CreateGrant(
        Guid userId,
        Guid? tenantId = null,
        string? scopeType = null,
        string? scopeId = null,
        string? role = null,
        string? permission = null,
        DateTimeOffset? createdAt = null,
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
            CreatedAt = createdAt ?? Now,
            ExpiresAt = expiresAt,
            Metadata = metadata
        };
    }
}
