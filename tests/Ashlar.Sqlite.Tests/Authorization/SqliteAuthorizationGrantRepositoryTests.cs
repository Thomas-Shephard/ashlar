using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Microsoft.Extensions.DependencyInjection;

namespace Ashlar.Sqlite.Tests.Authorization;

internal sealed class SqliteAuthorizationGrantRepositoryTests : SqliteTestBase
{
    private static readonly DateTimeOffset Now = new(2026, 5, 17, 12, 0, 0, TimeSpan.Zero);
    private static readonly string[] GlobalPermissions = ["global.read"];
    private ServiceProvider _serviceProvider = null!;
    private Guid _userId;

    [SetUp]
    public async Task SetUp()
    {
        var services = new ServiceCollection();
        services.AddAshlarSqlite(GetConnectionString());
        _serviceProvider = services.BuildServiceProvider();
        await _serviceProvider.InitializeAshlarSqliteSchemaAsync();
        _userId = (await CreateUserAsync()).Id;
    }

    [TearDown]
    public async Task TearDownAsync()
    {
        await _serviceProvider.DisposeAsync();
    }

    [Test]
    public async Task CreateListGetAndRevokeGrantRoundTrips()
    {
        var repository = GetRepository();
        var grant = CreateGrant(permission: "posts.edit", metadata: """{"source":"test"}""");

        await repository.CreateGrantAsync(grant);
        var listed = await repository.ListGrantsAsync(new ListAuthorizationGrantsRequest(_userId, ActiveOnly: true));
        var fetched = await repository.GetGrantAsync(grant.Id);
        var revoked = await repository.RevokeGrantAsync(grant.Id, grant.TenantId, Now.AddMinutes(1));
        var revokedAgain = await repository.RevokeGrantAsync(grant.Id, grant.TenantId, Now.AddMinutes(2));
        var activeAfterRevoke = await repository.ListGrantsAsync(new ListAuthorizationGrantsRequest(_userId, ActiveOnly: true));
        var fetchedRevoked = await repository.GetGrantAsync(grant.Id);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(listed, Has.Count.EqualTo(1));
            Assert.That(fetched?.Permission, Is.EqualTo("posts.edit"));
            Assert.That(fetched?.Metadata, Is.EqualTo("""{"source":"test"}"""));
            Assert.That(revoked, Is.True);
            Assert.That(revokedAgain, Is.False);
            Assert.That(activeAfterRevoke, Is.Empty);
            Assert.That(fetchedRevoked?.RevokedAt, Is.EqualTo(Now.AddMinutes(1)));
        }
    }

    [Test]
    public async Task ListGrantsAsyncSupportsTenantScopeShapeAndActiveFilters()
    {
        var repository = GetRepository();
        var tenantId = Guid.NewGuid();
        var tenantUser = await CreateUserAsync(tenantId);
        await repository.CreateGrantAsync(CreateGrantForUser(tenantUser.Id, tenantId, "project", "abc", role: "reviewer"));
        await repository.CreateGrantAsync(CreateGrantForUser(tenantUser.Id, tenantId, "project", "other", role: "operator"));
        await repository.CreateGrantAsync(CreateGrant(permission: "global.read"));
        await repository.CreateGrantAsync(CreateGrantForUser(tenantUser.Id, tenantId, permission: "expired", expiresAt: Now.AddSeconds(-1)));
        var revoked = CreateGrantForUser(tenantUser.Id, tenantId, permission: "revoked");
        await repository.CreateGrantAsync(revoked);
        await repository.RevokeGrantAsync(revoked.Id, revoked.TenantId, Now.AddSeconds(1));

        var scoped = await repository.ListGrantsAsync(new ListAuthorizationGrantsRequest(tenantUser.Id, tenantId, "project", "abc", ActiveOnly: true));
        var permissionGlobal = await repository.ListGrantsAsync(new ListAuthorizationGrantsRequest(_userId, ActiveOnly: true, ExactMatch: true));
        var active = await repository.ListGrantsAsync(new ListAuthorizationGrantsRequest(tenantUser.Id, ActiveOnly: true));
        var all = await repository.ListGrantsAsync(new ListAuthorizationGrantsRequest(tenantUser.Id));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scoped, Has.Count.EqualTo(1));
            Assert.That(scoped[0].Role, Is.EqualTo("reviewer"));
            Assert.That(scoped[0].Permission, Is.Null);
            Assert.That(permissionGlobal.Select(grant => grant.Permission), Is.EquivalentTo(GlobalPermissions));
            Assert.That(active.Select(grant => grant.Permission), Does.Not.Contain("expired"));
            Assert.That(active.Select(grant => grant.Permission), Does.Not.Contain("revoked"));
            Assert.That(all, Has.Count.EqualTo(4));
        }
    }

    [Test]
    public async Task ListGrantsAsyncIsolatesUsersTenantsAndScopes()
    {
        var repository = GetRepository();
        var tenantId = Guid.NewGuid();
        var otherTenantId = Guid.NewGuid();
        var tenantUser = await CreateUserAsync(tenantId);
        var otherTenantUser = await CreateUserAsync(otherTenantId);
        var otherUser = await CreateUserAsync(tenantId);
        await repository.CreateGrantAsync(CreateGrantForUser(tenantUser.Id, tenantId, "project", "abc", permission: "matching"));
        await repository.CreateGrantAsync(CreateGrantForUser(otherTenantUser.Id, otherTenantId, "project", "abc", permission: "other-tenant"));
        await repository.CreateGrantAsync(CreateGrantForUser(tenantUser.Id, tenantId, "project", "other", permission: "other-scope"));
        await repository.CreateGrantAsync(CreateGrantForUser(otherUser.Id, tenantId, "project", "abc", permission: "other-user"));

        var grants = await repository.ListGrantsAsync(new ListAuthorizationGrantsRequest(tenantUser.Id, tenantId, "project", "abc", ActiveOnly: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(grants, Has.Count.EqualTo(1));
            Assert.That(grants[0].Permission, Is.EqualTo("matching"));
        }
    }

    [Test]
    public async Task GrantCreateRollsBackWithTransaction()
    {
        var grant = CreateGrant(permission: "rollback");

        await using (var scope = _serviceProvider.CreateAsyncScope())
        {
            var transactions = scope.ServiceProvider.GetRequiredService<IAshlarTransactionProvider>();
            var repository = scope.ServiceProvider.GetRequiredService<IAuthorizationGrantRepository>();
            await using var transaction = await transactions.BeginTransactionAsync();
            await repository.CreateGrantAsync(grant);
            await transaction.RollbackAsync();
        }

        Assert.That(await GetRepository().GetGrantAsync(grant.Id), Is.Null);
    }

    [Test]
    public async Task RepositoryValidatesArgumentsAndMissingRows()
    {
        var repository = GetRepository();

        Assert.Throws<ArgumentNullException>(() => _ = new SqliteAuthorizationGrantRepository(null!));
        Assert.ThrowsAsync<ArgumentNullException>(async () => await repository.CreateGrantAsync(null!));
        Assert.ThrowsAsync<ArgumentNullException>(async () => await repository.ListGrantsAsync(null!));

        var systemClockRepository = new SqliteAuthorizationGrantRepository(_serviceProvider.GetRequiredService<ISqliteConnectionProvider>());
        var grant = CreateGrant(permission: "system-clock", expiresAt: DateTimeOffset.UtcNow.AddDays(1));
        await repository.CreateGrantAsync(grant);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(await repository.GetGrantAsync(Guid.NewGuid()), Is.Null);
            Assert.That(await systemClockRepository.ListGrantsAsync(new ListAuthorizationGrantsRequest(_userId, ActiveOnly: true)), Has.Count.EqualTo(1));
        }
    }

    private SqliteAuthorizationGrantRepository GetRepository()
    {
        return new SqliteAuthorizationGrantRepository(_serviceProvider.GetRequiredService<ISqliteConnectionProvider>(), new FixedTimeProvider(Now));
    }

    private Task<AshlarUser> CreateUserAsync()
    {
        return CreateUserAsync(null);
    }

    private async Task<AshlarUser> CreateUserAsync(Guid? tenantId)
    {
        var user = new AshlarUser
        {
            Id = Guid.NewGuid(),
            Email = $"{Guid.NewGuid():N}@example.com",
            IsActive = true,
            TenantId = tenantId
        };
        await _serviceProvider.GetRequiredService<IUserRepository>().CreateUserAsync(user);
        return user;
    }

    private AuthorizationGrant CreateGrant(
        Guid? tenantId = null,
        string? scopeType = null,
        string? scopeId = null,
        string? role = null,
        string? permission = null,
        DateTimeOffset? expiresAt = null,
        string? metadata = null)
    {
        return CreateGrantForUser(_userId, tenantId, scopeType, scopeId, role, permission, expiresAt, metadata);
    }

    private static AuthorizationGrant CreateGrantForUser(
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

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
