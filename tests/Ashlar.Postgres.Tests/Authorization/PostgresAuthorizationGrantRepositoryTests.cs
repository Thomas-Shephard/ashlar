using System.Diagnostics.CodeAnalysis;
using Ashlar.Authorization.Models;
using Dapper;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Postgres.Tests.Authorization;

internal sealed class PostgresAuthorizationGrantRepositoryTests : PostgresTestBase
{
    private static readonly Guid UserId = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
    private readonly DateTimeOffset _now = new(2026, 5, 8, 12, 0, 0, TimeSpan.Zero);
    private FakeTimeProvider _timeProvider;
    private PostgresAuthorizationGrantRepository _repository;

    public override async Task OneTimeSetUp()
    {
        await base.OneTimeSetUp();

        var services = new ServiceCollection();
        services.AddAshlarPostgres(GetConnectionString());
        await services.BuildServiceProvider().InitializeAshlarPostgresSchemaAsync();
    }

    [SetUp]
    public async Task SetUpAsync()
    {
        _timeProvider = new FakeTimeProvider(_now);
        _repository = new PostgresAuthorizationGrantRepository(new PostgresTransactionManager(GetDataSource()), _timeProvider);

        await using var connection = await GetDataSource().OpenConnectionAsync();
        await connection.ExecuteAsync("TRUNCATE ashlar_authorization_grants, ashlar_users CASCADE;");
        await connection.ExecuteAsync(
            "INSERT INTO ashlar_users (id, email, normalized_email, created_at) VALUES (@id, 'authz@example.com', 'authz@example.com', @now)",
            new { id = UserId, now = _now });
    }

    [Test]
    public async Task CreateListGetAndRevokeGrantRoundTrips()
    {
        var grant = CreateGrant(permission: "posts.edit", metadata: """{"source":"test"}""");

        await _repository.CreateGrantAsync(grant);
        var listed = await _repository.ListGrantsAsync(new ListAuthorizationGrantsRequest(UserId, ActiveOnly: true));
        var fetched = await _repository.GetGrantAsync(grant.Id, grant.TenantId);
        var revoked = await _repository.RevokeGrantAsync(grant.Id, grant.TenantId, _now.AddMinutes(1));
        var revokedAgain = await _repository.RevokeGrantAsync(grant.Id, grant.TenantId, _now.AddMinutes(2));
        var activeAfterRevoke = await _repository.ListGrantsAsync(new ListAuthorizationGrantsRequest(UserId, ActiveOnly: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(listed, Has.Count.EqualTo(1));
            Assert.That(fetched?.Permission, Is.EqualTo("posts.edit"));
            Assert.That(fetched?.Metadata, Does.Contain("source"));
            Assert.That(revoked, Is.True);
            Assert.That(revokedAgain, Is.False);
            Assert.That(activeAfterRevoke, Is.Empty);
        }
    }

    [Test]
    public async Task ListGrantsAsyncSupportsTenantScopeAndActiveFilters()
    {
        var tenantId = Guid.NewGuid();
        var tenantUserId = await CreateUserAsync(tenantId);
        await _repository.CreateGrantAsync(CreateGrantForUser(tenantUserId, tenantId, "project", "abc", role: "reviewer"));
        await _repository.CreateGrantAsync(CreateGrantForUser(tenantUserId, tenantId, "project", "other", role: "reviewer"));
        await _repository.CreateGrantAsync(CreateGrantForUser(tenantUserId, tenantId, permission: "expired", expiresAt: _now.AddSeconds(-1)));

        var scoped = await _repository.ListGrantsAsync(new ListAuthorizationGrantsRequest(tenantUserId, tenantId, "project", "abc", ActiveOnly: true));
        var all = await _repository.ListGrantsAsync(new ListAuthorizationGrantsRequest(tenantUserId, tenantId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scoped, Has.Count.EqualTo(1));
            Assert.That(scoped[0].ScopeId, Is.EqualTo("abc"));
            Assert.That(all, Has.Count.EqualTo(3));
        }
    }

    [Test]
    public async Task ListGrantsAsyncExactMatchFiltersGlobalGrantsInDatabase()
    {
        var tenantId = Guid.NewGuid();
        var tenantUserId = await CreateUserAsync(tenantId);
        await _repository.CreateGrantAsync(CreateGrant(permission: "global.read"));
        await _repository.CreateGrantAsync(CreateGrantForUser(tenantUserId, tenantId, "project", "abc", permission: "scoped.read"));

        var exactGlobal = await _repository.ListGrantsAsync(new ListAuthorizationGrantsRequest(UserId, ActiveOnly: true, ExactMatch: true));
        var broad = await _repository.ListGrantsAsync(new ListAuthorizationGrantsRequest(UserId, ActiveOnly: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(exactGlobal, Has.Count.EqualTo(1));
            Assert.That(exactGlobal[0].Permission, Is.EqualTo("global.read"));
            Assert.That(broad, Has.Count.EqualTo(1));
        }
    }

    [Test]
    public async Task ListGrantsAsyncUsesSystemClockWhenClockIsNotProvided()
    {
        var repository = new PostgresAuthorizationGrantRepository(new PostgresTransactionManager(GetDataSource()));
        await repository.CreateGrantAsync(CreateGrant(permission: "read"));

        var grants = await repository.ListGrantsAsync(new ListAuthorizationGrantsRequest(UserId, ActiveOnly: true));

        Assert.That(grants, Has.Count.EqualTo(1));
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public async Task RepositoryRejectsNullArguments()
    {
        Assert.Throws<ArgumentNullException>(() => _ = new PostgresAuthorizationGrantRepository(null!));
        Assert.ThrowsAsync<ArgumentNullException>(() => _repository.CreateGrantAsync(null!));
        Assert.ThrowsAsync<ArgumentNullException>(() => _repository.ListGrantsAsync(null!));

        var missing = await _repository.GetGrantAsync(Guid.NewGuid(), null);

        Assert.That(missing, Is.Null);
    }

    [Test]
    public void AddAshlarPostgresAuthorizationRegistersRepository()
    {
        var services = new ServiceCollection();

        services.AddAshlarPostgresAuthorization("Host=localhost;Database=ashlar;Username=ashlar;Password=ashlar");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(services, Has.Some.Matches<ServiceDescriptor>(descriptor =>
                descriptor.ServiceType == typeof(Ashlar.Authorization.Abstractions.IAuthorizationGrantRepository)
                && descriptor.ImplementationType == typeof(PostgresAuthorizationGrantRepository)
                && descriptor.Lifetime == ServiceLifetime.Scoped));
            Assert.That(services, Has.Some.Matches<ServiceDescriptor>(descriptor =>
                descriptor.ServiceType == typeof(IPostgresConnectionProvider)
                && descriptor.Lifetime == ServiceLifetime.Scoped));
        }
    }

    [Test]
    public void AddAshlarPostgresAuthorizationRegistersRepositoryWithDataSource()
    {
        var services = new ServiceCollection();

        services.AddAshlarPostgresAuthorization(GetDataSource());

        Assert.That(services, Has.Some.Matches<ServiceDescriptor>(descriptor =>
            descriptor.ServiceType == typeof(Ashlar.Authorization.Abstractions.IAuthorizationGrantRepository)
            && descriptor.ImplementationType == typeof(PostgresAuthorizationGrantRepository)
            && descriptor.Lifetime == ServiceLifetime.Scoped));
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
        return CreateGrantForUser(UserId, tenantId, scopeType, scopeId, role, permission, expiresAt, metadata);
    }

    private AuthorizationGrant CreateGrantForUser(
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
            CreatedAt = _now,
            ExpiresAt = expiresAt,
            Metadata = metadata
        };
    }

    private async Task<Guid> CreateUserAsync(Guid? tenantId)
    {
        var id = Guid.NewGuid();
        await using var connection = await GetDataSource().OpenConnectionAsync();
        await connection.ExecuteAsync(
            "INSERT INTO ashlar_users (id, email, normalized_email, tenant_id, created_at) VALUES (@id, @email, @email, @tenantId, @now)",
            new { id, email = $"{id:N}@example.com", tenantId, now = _now });
        return id;
    }
}
