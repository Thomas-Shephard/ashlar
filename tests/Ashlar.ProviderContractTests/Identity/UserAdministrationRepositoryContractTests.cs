namespace Ashlar.ProviderContractTests.Identity;

internal abstract class UserAdministrationRepositoryContractTests : ProviderContractFixture
{
    [Test]
    public async Task SearchMatchesExactPartialAndCaseInsensitiveEmail()
    {
        await using var scope = CreateAsyncScope();
        var identity = GetUserRepository(scope.ServiceProvider);
        var repository = GetUserAdministrationRepository(scope.ServiceProvider);
        var expected = await CreateUserAsync(identity, "Mixed.Admin@example.com");
        await CreateUserAsync(identity, "other@example.com");

        var exact = await repository.SearchUsersAsync(new SearchUsersRequest { IncludeAllTenants = true, Query = "mixed.admin@example.com", Limit = 10 });
        var partial = await repository.SearchUsersAsync(new SearchUsersRequest { IncludeAllTenants = true, Query = "ADMIN@EXAMPLE", Limit = 10 });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(exact.Select(user => user.UserId), Does.Contain(expected.Id));
            Assert.That(exact.Single(user => user.UserId == expected.Id).DisplayEmail, Is.EqualTo("Mixed.Admin@example.com"));
            Assert.That(partial.Select(user => user.UserId), Does.Contain(expected.Id));
            Assert.That(partial.Single(user => user.UserId == expected.Id).DisplayEmail, Is.EqualTo("Mixed.Admin@example.com"));
            Assert.That(partial.Select(user => user.DisplayEmail), Does.Not.Contain("other@example.com"));
        }
    }

    [Test]
    public async Task DetailReturnsDisplayEmailRatherThanNormalizedLookupEmail()
    {
        await using var scope = CreateAsyncScope();
        var identity = GetUserRepository(scope.ServiceProvider);
        var repository = GetUserAdministrationRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(identity, "Admin.Detail@Example.COM");

        var detail = await repository.GetUserSummaryAsync(new UserAdministrationDetailRequest(user.Id, IncludeAllTenants: true));

        Assert.That(detail?.DisplayEmail, Is.EqualTo("Admin.Detail@Example.COM"));
    }

    [Test]
    public async Task SearchMatchesName()
    {
        await using var scope = CreateAsyncScope();
        var identity = GetUserRepository(scope.ServiceProvider);
        var repository = GetUserAdministrationRepository(scope.ServiceProvider);
        var expected = await CreateNamedUserAsync(identity, "name-match@example.com", "Alex Operations");
        await CreateNamedUserAsync(identity, "name-miss@example.com", "Casey Support");

        var result = await repository.SearchUsersAsync(new SearchUsersRequest { IncludeAllTenants = true, Query = "operations", Limit = 10 });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Select(user => user.UserId), Does.Contain(expected.Id));
            Assert.That(result.Select(user => user.DisplayEmail), Does.Not.Contain("name-miss@example.com"));
        }
    }

    [Test]
    public async Task TenantScopeIsIsolated()
    {
        await using var scope = CreateAsyncScope();
        var identity = GetUserRepository(scope.ServiceProvider);
        var repository = GetUserAdministrationRepository(scope.ServiceProvider);
        var tenant1 = Guid.NewGuid();
        var tenant2 = Guid.NewGuid();
        var user1 = await CreateUserAsync(identity, "tenant-same@example.com", tenant1);
        await CreateUserAsync(identity, "tenant-same@example.com", tenant2);

        var result = await repository.SearchUsersAsync(new SearchUsersRequest { Query = "tenant-same", Tenant = new TenantContext(tenant1), Limit = 10 });

        Assert.That(result.Select(user => user.UserId), Is.EqualTo(new[] { user1.Id }));
    }

    [Test]
    public async Task GlobalTenantScopeSearchesOnlyGlobalUsers()
    {
        await using var scope = CreateAsyncScope();
        var identity = GetUserRepository(scope.ServiceProvider);
        var repository = GetUserAdministrationRepository(scope.ServiceProvider);
        var global = await CreateUserAsync(identity, "global-scope@example.com");
        await CreateUserAsync(identity, "global-scope@example.com", Guid.NewGuid());

        var result = await repository.SearchUsersAsync(new SearchUsersRequest { Query = "global-scope", Tenant = TenantContext.Global, Limit = 10 });

        Assert.That(result.Select(user => user.UserId), Is.EqualTo(new[] { global.Id }));
    }

    [Test]
    public async Task SearchRequiresExplicitTenantScopeOrAllTenantsMode()
    {
        await using var scope = CreateAsyncScope();
        var repository = GetUserAdministrationRepository(scope.ServiceProvider);

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentException>(() => repository.SearchUsersAsync(new SearchUsersRequest { Limit = 10 }));
            Assert.ThrowsAsync<ArgumentException>(() => repository.SearchUsersAsync(new SearchUsersRequest { Tenant = TenantContext.Global, IncludeAllTenants = true, Limit = 10 }));
        }
    }

    [Test]
    public async Task ActiveFilterIsApplied()
    {
        await using var scope = CreateAsyncScope();
        var identity = GetUserRepository(scope.ServiceProvider);
        var repository = GetUserAdministrationRepository(scope.ServiceProvider);
        var active = await CreateUserAsync(identity, "active-filter@example.com", AccountState: UserAccountState.Active);
        await CreateUserAsync(identity, "inactive-filter@example.com", AccountState: UserAccountState.Disabled);

        var result = await repository.SearchUsersAsync(new SearchUsersRequest { IncludeAllTenants = true, Query = "filter@example.com", AccountState = UserAccountState.Active, Limit = 10 });

        Assert.That(result.Select(user => user.UserId), Is.EqualTo(new[] { active.Id }));
    }

    [Test]
    public async Task EmailVerifiedFilterIsApplied()
    {
        await using var scope = CreateAsyncScope();
        var identity = GetUserRepository(scope.ServiceProvider);
        var repository = GetUserAdministrationRepository(scope.ServiceProvider);
        var verified = await CreateNamedUserAsync(identity, "verified-filter@example.com", "Verified", emailVerifiedAt: DateTimeOffset.UtcNow);
        await CreateNamedUserAsync(identity, "unverified-filter@example.com", "Unverified");

        var result = await repository.SearchUsersAsync(new SearchUsersRequest { IncludeAllTenants = true, Query = "filter@example.com", IsEmailVerified = true, Limit = 10 });

        Assert.That(result.Select(user => user.UserId), Is.EqualTo(new[] { verified.Id }));
    }

    [Test]
    public async Task EmailUnverifiedFilterIsApplied()
    {
        await using var scope = CreateAsyncScope();
        var identity = GetUserRepository(scope.ServiceProvider);
        var repository = GetUserAdministrationRepository(scope.ServiceProvider);
        await CreateNamedUserAsync(identity, "verified-only@example.com", "Verified", emailVerifiedAt: DateTimeOffset.UtcNow);
        var unverified = await CreateNamedUserAsync(identity, "unverified-only@example.com", "Unverified");

        var result = await repository.SearchUsersAsync(new SearchUsersRequest { IncludeAllTenants = true, Query = "verified-only@example.com", IsEmailVerified = false, Limit = 10 });

        Assert.That(result.Select(user => user.UserId), Is.EqualTo(new[] { unverified.Id }));
    }

    [Test]
    public async Task GetUserSummaryReturnsUpdatedAtAfterUserUpdate()
    {
        await using var scope = CreateAsyncScope();
        var identity = GetUserRepository(scope.ServiceProvider);
        var repository = GetUserAdministrationRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(identity, "updated-at@example.com");
        await identity.UpdateUserAsync(user with { Name = "Updated" });

        var result = await repository.GetUserSummaryAsync(new UserAdministrationDetailRequest(user.Id, IncludeAllTenants: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result?.Name, Is.EqualTo("Updated"));
            Assert.That(result?.UpdatedAt, Is.Not.Null);
        }
    }

    [Test]
    public async Task GetUserSummaryAppliesExplicitTenantScopeWithoutLeakingExistence()
    {
        await using var scope = CreateAsyncScope();
        var identity = GetUserRepository(scope.ServiceProvider);
        var repository = GetUserAdministrationRepository(scope.ServiceProvider);
        var tenantId = Guid.NewGuid();
        var otherTenantId = Guid.NewGuid();
        var user = await CreateUserAsync(identity, "scoped-detail@example.com", tenantId);
        var globalUser = await CreateUserAsync(identity, "global-detail@example.com");

        var inScope = await repository.GetUserSummaryAsync(new UserAdministrationDetailRequest(user.Id, new TenantContext(tenantId)));
        var outOfScope = await repository.GetUserSummaryAsync(new UserAdministrationDetailRequest(user.Id, new TenantContext(otherTenantId)));
        var globalScope = await repository.GetUserSummaryAsync(new UserAdministrationDetailRequest(user.Id, TenantContext.Global));
        var globalInScope = await repository.GetUserSummaryAsync(new UserAdministrationDetailRequest(globalUser.Id, TenantContext.Global));
        var allTenants = await repository.GetUserSummaryAsync(new UserAdministrationDetailRequest(user.Id, IncludeAllTenants: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(inScope?.UserId, Is.EqualTo(user.Id));
            Assert.That(outOfScope, Is.Null);
            Assert.That(globalScope, Is.Null);
            Assert.That(globalInScope?.UserId, Is.EqualTo(globalUser.Id));
            Assert.That(allTenants?.UserId, Is.EqualTo(user.Id));
        }
    }

    [Test]
    public async Task GetUserSummaryRequiresExplicitTenantScopeOrAllTenantsMode()
    {
        await using var scope = CreateAsyncScope();
        var repository = GetUserAdministrationRepository(scope.ServiceProvider);
        var userId = Guid.NewGuid();

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentException>(() => repository.GetUserSummaryAsync(new UserAdministrationDetailRequest(userId)));
            Assert.ThrowsAsync<ArgumentException>(() => repository.GetUserSummaryAsync(new UserAdministrationDetailRequest(userId, TenantContext.Global, IncludeAllTenants: true)));
        }
    }

    [Test]
    public async Task SearchOrderingIsDeterministicByEmailThenUserId()
    {
        await using var scope = CreateAsyncScope();
        var identity = GetUserRepository(scope.ServiceProvider);
        var repository = GetUserAdministrationRepository(scope.ServiceProvider);
        var beta = await CreateUserAsync(identity, "z-admin-order@example.com");
        var alpha1 = await CreateUserAsync(identity, "a-admin-order@example.com", Guid.NewGuid());
        var alpha2 = await CreateUserAsync(identity, "a-admin-order@example.com", Guid.NewGuid());

        var result = await repository.SearchUsersAsync(new SearchUsersRequest { IncludeAllTenants = true, Query = "admin-order@example.com", Limit = 10 });
        var expected = new[] { alpha1, alpha2, beta }.OrderBy(user => user.DisplayEmail, StringComparer.OrdinalIgnoreCase).ThenBy(user => user.Id).Select(user => user.Id);

        Assert.That(result.Select(user => user.UserId), Is.EqualTo(expected));
    }

    [Test]
    public async Task LimitOffsetSupportPaging()
    {
        await using var scope = CreateAsyncScope();
        var identity = GetUserRepository(scope.ServiceProvider);
        var repository = GetUserAdministrationRepository(scope.ServiceProvider);
        var users = new List<AshlarUser>();
        for (var i = 0; i < 5; i++)
        {
            users.Add(await CreateUserAsync(identity, $"page-{i}@example.com"));
        }

        var result = await repository.SearchUsersAsync(new SearchUsersRequest { IncludeAllTenants = true, Query = "page-", Limit = 2, Offset = 1 });
        var expected = users.OrderBy(user => user.DisplayEmail, StringComparer.OrdinalIgnoreCase).ThenBy(user => user.Id).Skip(1).Take(2).Select(user => user.Id);

        Assert.That(result.Select(user => user.UserId), Is.EqualTo(expected));
    }

    [Test]
    public async Task UserSummariesDoNotExposeCredentialSecrets()
    {
        await using var scope = CreateAsyncScope();
        var identity = GetUserRepository(scope.ServiceProvider);
        var credentials = GetCredentialRepository(scope.ServiceProvider);
        var repository = GetUserAdministrationRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(identity, "secret-search@example.com");
        var credential = CreateCredential(user.Id, ProviderType.Local, ProviderType.Local.Value);
        credential.CredentialValue = "password-hash";
        await credentials.CreateCredentialAsync(credential);

        var search = await repository.SearchUsersAsync(new SearchUsersRequest { IncludeAllTenants = true, Query = "secret-search", Limit = 10 });
        var detail = await repository.GetUserSummaryAsync(new UserAdministrationDetailRequest(user.Id, IncludeAllTenants: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(search.Single().DisplayEmail, Is.EqualTo(user.DisplayEmail));
            Assert.That(detail?.DisplayEmail, Is.EqualTo(user.DisplayEmail));
        }
    }

    [Test]
    public async Task GetUserSummaryReturnsNullForMissingUser()
    {
        await using var scope = CreateAsyncScope();
        var repository = GetUserAdministrationRepository(scope.ServiceProvider);

        Assert.That(await repository.GetUserSummaryAsync(new UserAdministrationDetailRequest(Guid.NewGuid(), IncludeAllTenants: true)), Is.Null);
    }

    private static async Task<AshlarUser> CreateNamedUserAsync(
        IUserRepository repository,
        string email,
        string name,
        Guid? tenantId = null,
        DateTimeOffset? emailVerifiedAt = null)
    {
        var user = new AshlarUser
        {
            Id = Guid.NewGuid(),
            DisplayEmail = email,
            Name = name,
            AccountState = UserAccountState.Active,
            TenantId = tenantId,
            EmailVerifiedAt = emailVerifiedAt
        };

        await repository.CreateUserAsync(user);
        return user;
    }
}
