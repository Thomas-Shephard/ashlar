using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Ashlar.Identity.Abstractions.Services;
using Ashlar.Identity.Models.AccountLockout;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Ashlar.Sqlite.Tests;

internal sealed class SecurityMutationAuditAtomicityTests
{
    private SqliteContractDatabase? _database;

    [TearDown]
    public void TearDown()
    {
        _database?.Delete();
        _database = null;
    }

    [Test]
    public async Task AuthorizationGrantCreateRollsBackWhenRequiredAuditFails()
    {
        _database = await CreateDatabaseAsync(services => services.AddAshlarAuthorization());
        var provider = _database.ServiceProvider;
        var user = await CreateUserAsync(provider);

        Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await provider.GetRequiredService<IAuthorizationGrantService>().CreateGrantAsync(
                new CreateAuthorizationGrantRequest(user.Id, Audit(), Permission: "posts.read")));

        var grants = await provider.GetRequiredService<IAuthorizationGrantRepository>().ListGrantsAsync(new ListAuthorizationGrantsRequest(user.Id));
        Assert.That(grants, Is.Empty);
    }

    [Test]
    public async Task AuthorizationGrantRevokeRollsBackWhenRequiredAuditFails()
    {
        _database = await CreateDatabaseAsync(services => services.AddAshlarAuthorization());
        var provider = _database.ServiceProvider;
        var user = await CreateUserAsync(provider);
        var grant = new AuthorizationGrant
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            Permission = "posts.read",
            CreatedAt = DateTimeOffset.UtcNow
        };
        await provider.GetRequiredService<IAuthorizationGrantRepository>().CreateGrantAsync(grant);

        Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await provider.GetRequiredService<IAuthorizationGrantService>().RevokeGrantAsync(
                new RevokeAuthorizationGrantRequest(grant.Id, Audit())));

        var stored = await provider.GetRequiredService<IAuthorizationGrantRepository>().GetGrantAsync(grant.Id, null);
        Assert.That(stored?.RevokedAt, Is.Null);
    }

    [Test]
    public async Task InvitationAdminRevokeRollsBackWhenRequiredAuditFails()
    {
        _database = await CreateDatabaseAsync(services => services.AddAshlarInvitations());
        var provider = _database.ServiceProvider;
        var invitation = CreateInvitation();
        await provider.GetRequiredService<IInvitationRepository>().CreateInvitationAsync(invitation);

        Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await provider.GetRequiredService<IInvitationAdministrationService>().RevokeInvitationAsync(
                new RevokeInvitationAdministrationRequest(invitation.Id, IncludeAllTenants: true, Audit: Audit())));

        var stored = await provider.GetRequiredService<IInvitationRepository>().GetInvitationByTokenHashAsync(invitation.TokenHash);
        Assert.That(stored?.RevokedAt, Is.Null);
    }

    [Test]
    public async Task AccountLockoutResetRollsBackWhenRequiredAuditFails()
    {
        _database = await CreateDatabaseAsync(services => services.AddAshlarIdentity());
        var provider = _database.ServiceProvider;
        var repository = provider.GetRequiredService<IAccountLockoutRepository>();
        var tenant = new TenantContext(Guid.NewGuid());
        var userId = (await CreateUserAsync(provider, tenant.TenantId)).Id;
        var authProvider = new AuthenticationProviderKey("password", "local");
        await repository.RecordFailureAsync(userId, tenant.TenantId, authProvider, DateTimeOffset.UtcNow, 1, TimeSpan.FromMinutes(5));

        Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await provider.GetRequiredService<IAccountLockoutAdministrationService>()
                .ResetLockoutAsync(userId, authProvider, new ResetAccountLockoutRequest(tenant, Audit())));

        var stored = await repository.GetAsync(userId, tenant.TenantId, authProvider);
        Assert.That(stored, Is.Not.Null);
    }

    [Test]
    public async Task SqliteRateLimitResetRollsBackWhenRequiredAuditFails()
    {
        _database = await CreateDatabaseAsync(services => services.AddAshlarSqliteRateLimiting());
        var provider = _database.ServiceProvider;
        await provider.GetRequiredService<IAuthenticationRateLimiter>().CheckAsync(
            new RateLimitAttempt { Purpose = "login", Key = "203.0.113.10" },
            new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(5) });
        var bucket = (await provider.GetRequiredService<IAuthenticationRateLimitAdministrationRepository>().SearchBucketsAsync(
            new SearchAuthenticationRateLimitBucketsRequest { Purpose = "login", Limit = 10 },
            DateTimeOffset.UtcNow)).Single();

        Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await provider.GetRequiredService<IAuthenticationRateLimitAdministrationService>().ResetBucketAsync(
                new ResetAuthenticationRateLimitBucketRequest(bucket.BucketId, bucket.Purpose, Audit())));

        var stored = await provider.GetRequiredService<IAuthenticationRateLimitAdministrationRepository>().GetBucketAsync(
            new AuthenticationRateLimitBucketLookupRequest(bucket.BucketId, bucket.Purpose),
            DateTimeOffset.UtcNow);
        Assert.That(stored, Is.Not.Null);
    }

    private static async Task<SqliteContractDatabase> CreateDatabaseAsync(Action<IServiceCollection>? configure = null)
    {
        return await SqliteContractDatabase.CreateAsync(services =>
        {
            configure?.Invoke(services);
            services.Replace(ServiceDescriptor.Scoped<ISecurityEventSink, ThrowingSecurityEventSink>());
        });
    }

    private static async Task<AshlarUser> CreateUserAsync(IServiceProvider provider, Guid? tenantId = null)
    {
        var user = new AshlarUser
        {
            Id = Guid.NewGuid(),
            DisplayEmail = $"{Guid.NewGuid():N}@example.test",
            AccountState = UserAccountState.Active,
            TenantId = tenantId
        };
        await provider.GetRequiredService<IUserRepository>().CreateUserAsync(user);
        return user;
    }

    private static UserInvitation CreateInvitation()
    {
        var now = DateTimeOffset.UtcNow;
        return new UserInvitation
        {
            Id = Guid.NewGuid(),
            DisplayEmail = "invitee@example.test",
            TokenHash = Guid.NewGuid().ToString("N"),
            CreatedAt = now,
            ExpiresAt = now.AddDays(1),
            Version = Guid.NewGuid().ToString("N")
        };
    }

    private static AuditContext Audit()
    {
        return new AuditContext(ActorUserId: Guid.NewGuid(), IpAddress: "203.0.113.10", UserAgent: "atomicity-test");
    }

    private sealed class ThrowingSecurityEventSink : ISecurityEventSink
    {
        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            throw new InvalidOperationException("required audit failed");
        }
    }
}
