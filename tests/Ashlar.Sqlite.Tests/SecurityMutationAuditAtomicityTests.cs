using Ashlar.Authorization.Models;
using Ashlar.Identity.Features.Mfa;
using Ashlar.Identity.Models.Mfa;
using Ashlar.Identity.Abstractions.Services;
using Ashlar.Identity.Models.AccountLockout;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Security.Tokens;
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
        _database = await CreateDatabaseAsync(services =>
        {
            services.AddAshlarIdentity();
            services.AddAshlarAuthorization();
            services.AddScoped<IAccountSecurityOperationAuthorizer, AllowOperations>();
        });
        var provider = _database.ServiceProvider;
        var user = await CreateUserAsync(provider);
        var actor = await CreateActorAsync(provider);

        Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await provider.GetRequiredService<IAuthorizationGrantService>().CreateGrantAsync(
                new CreateAuthorizationGrantRequest(user.Id, actor, actor.Audit, TenantContext.Global, permission: "posts.read")));

        var grants = await provider.GetRequiredService<IAuthorizationGrantRepository>().ListGrantsAsync(new ListAuthorizationGrantsRequest(user.Id));
        Assert.That(grants, Is.Empty);
    }

    [Test]
    public async Task AuthorizationGrantRevokeRollsBackWhenRequiredAuditFails()
    {
        _database = await CreateDatabaseAsync(services =>
        {
            services.AddAshlarIdentity();
            services.AddAshlarAuthorization();
            services.AddScoped<IAccountSecurityOperationAuthorizer, AllowOperations>();
        });
        var provider = _database.ServiceProvider;
        var user = await CreateUserAsync(provider);
        var actor = await CreateActorAsync(provider);
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
                new RevokeAuthorizationGrantRequest(grant.Id, actor, actor.Audit, TenantContext.Global)));

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
    public async Task InvitationServiceRevokeRollsBackWhenRequiredAuditFails()
    {
        _database = await CreateDatabaseAsync(services => services.AddAshlarInvitations());
        var provider = _database.ServiceProvider;
        var invitation = CreateInvitation();
        await provider.GetRequiredService<IInvitationRepository>().CreateInvitationAsync(invitation);

        Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await provider.GetRequiredService<IInvitationService>().RevokeInvitationsAsync(
                new RevokeInvitationsRequest { Email = invitation.DisplayEmail, Tenant = TenantContext.Global, Audit = Audit() }));

        var stored = await provider.GetRequiredService<IInvitationRepository>().GetInvitationByTokenHashAsync(invitation.TokenHash);
        Assert.That(stored?.RevokedAt, Is.Null);
    }

    [Test]
    public async Task InvitationAcceptRollsBackWhenRequiredAuditFails()
    {
        const string token = "known-invitation-token";
        var email = $"{Guid.NewGuid():N}@example.test";

        _database = await CreateDatabaseAsync(services => services.AddAshlarInvitations());
        var provider = _database.ServiceProvider;
        await provider.GetRequiredService<IUserRepository>().CreateUserAsync(new AshlarUser
        {
            Id = Guid.NewGuid(),
            DisplayEmail = email,
            AccountState = UserAccountState.Disabled
        });
        var invitation = CreateInvitation(email, provider.GetRequiredService<ISecureTokenHasher>().HashToken(token));
        await provider.GetRequiredService<IInvitationRepository>().CreateInvitationAsync(invitation);

        Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await provider.GetRequiredService<IInvitationService>().AcceptInvitationAsync(new AcceptInvitationRequest { Token = token }));

        var stored = await provider.GetRequiredService<IInvitationRepository>().GetInvitationByTokenHashAsync(invitation.TokenHash);
        var user = await provider.GetRequiredService<IUserRepository>().GetUserByEmailAsync(email);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(stored?.AcceptedAt, Is.Null);
            Assert.That(user?.AccountState, Is.EqualTo(UserAccountState.Disabled));
        }
    }

    [Test]
    public async Task InvitationAcceptConcurrencyConflictPersistsFailureAuditWithoutMutation()
    {
        const string token = "known-invitation-token";
        var email = $"{Guid.NewGuid():N}@example.test";

        _database = await SqliteContractDatabase.CreateAsync(services =>
        {
            services.AddAshlarInvitations();
            services.AddAshlarSqliteAuditSink();
            services.AddSqliteProviderContractTestServices();
            services.AddScoped<SqliteInvitationRepository>();
            services.ReplaceAshlarProviderScoped<IInvitationRepository>(provider =>
                new ConflictOnUpdateInvitationRepository(provider.GetRequiredService<SqliteInvitationRepository>()));
        });
        var provider = _database.ServiceProvider;
        var invitation = CreateInvitation(email, provider.GetRequiredService<ISecureTokenHasher>().HashToken(token));
        await provider.GetRequiredService<SqliteInvitationRepository>().CreateInvitationAsync(invitation);

        var result = await provider.GetRequiredService<IInvitationService>().AcceptInvitationAsync(new AcceptInvitationRequest { Token = token });

        var stored = await provider.GetRequiredService<SqliteInvitationRepository>().GetInvitationByTokenHashAsync(invitation.TokenHash);
        var user = await provider.GetRequiredService<IUserRepository>().GetUserByEmailAsync(email);
        var auditEvent = (await provider.GetRequiredService<ISecurityEventAdministrationRepository>().SearchSecurityEventsAsync(new SearchSecurityEventsRequest
        {
            IncludeAllTenants = true,
            EventTypes = new HashSet<string> { AshlarSecurityEventTypes.InvitationAccepted },
            Outcome = SecurityEventOutcomes.Failure,
            FailureReason = AshlarFailureCodes.ConcurrencyConflict.Value,
            Limit = 10
        })).Single();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ConcurrencyConflict));
            Assert.That(stored?.AcceptedAt, Is.Null);
            Assert.That(user, Is.Null);
            Assert.That(auditEvent.Properties?["invitation_id"], Is.EqualTo(invitation.Id.ToString()));
        }
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
            services.Replace(ServiceDescriptor.Scoped<ThrowingSecurityEventSink, ThrowingSecurityEventSink>());
            services.ReplaceAshlarProviderScoped<IPersistentSecurityEventSink>(provider => provider.GetRequiredService<ThrowingSecurityEventSink>());
            services.AddAshlarDurableTransactionParticipant<IPersistentSecurityEventSink>();
            services.Replace(ServiceDescriptor.Scoped<SecurityEventFanOutSink>(provider => new SecurityEventFanOutSink(
                provider.GetRequiredService<ThrowingSecurityEventSink>(),
                transactionProvider: provider.GetRequiredService<AshlarDurableTransactionProvider>())));
            services.Replace(ServiceDescriptor.Scoped<ISecurityEventSink>(provider => provider.GetRequiredService<SecurityEventFanOutSink>()));
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

    private static UserInvitation CreateInvitation(string email = "invitee@example.test", string? tokenHash = null)
    {
        var now = DateTimeOffset.UtcNow;
        return new UserInvitation
        {
            Id = Guid.NewGuid(),
            DisplayEmail = email,
            TokenHash = tokenHash ?? Guid.NewGuid().ToString("N"),
            CreatedAt = now,
            ExpiresAt = now.AddDays(1),
            Version = Guid.NewGuid().ToString("N")
        };
    }

    private static AuditContext Audit()
    {
        return new AuditContext(ActorUserId: Guid.NewGuid(), IpAddress: "203.0.113.10", UserAgent: "atomicity-test");
    }

    private static async Task<AccountSecurityActorContext> CreateActorAsync(IServiceProvider provider)
    {
        const string token = "grant-atomicity-session-token";
        var actor = await CreateUserAsync(provider);
        var now = DateTimeOffset.UtcNow;
        var session = new AuthenticationSession
        {
            Id = Guid.NewGuid(),
            UserId = actor.Id,
            TokenHash = provider.GetRequiredService<ISecureTokenHasher>().HashToken(token),
            CreatedAt = now,
            ExpiresAt = now.AddHours(1),
            AdditionalVerificationAt = now
        };
        await provider.GetRequiredService<IAuthenticationSessionRepository>().CreateSessionAsync(session);
        var validated = await provider.GetRequiredService<IAuthenticationSessionService>().ValidateSessionAsync(token);
        var proof = provider.GetRequiredService<StepUpAuthenticationService>().CreateFreshMfaProof(
            validated.ValidatedSession!, new StepUpRequirement(TimeSpan.FromMinutes(5)), IAuthorizationGrantService.AdministrationProofPurpose).Value!;
        var audit = new AuditContext(actor.Id, UserAgent: "atomicity-test");
        return new AccountSecurityActorContext(actor.Id, TenantContext.Global, session.Id, proof, audit);
    }

    private sealed class ThrowingSecurityEventSink : IPersistentSecurityEventSink
    {
        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            return securityEvent.EventType == AshlarSecurityEventTypes.SessionValidated
                ? Task.CompletedTask
                : Task.FromException(new InvalidOperationException("required audit failed"));
        }
    }

    private sealed class AllowOperations : IAccountSecurityOperationAuthorizer
    {
        public ValueTask<bool> AuthorizeAsync(AccountSecurityAuthorizationContext context, CancellationToken cancellationToken = default) => ValueTask.FromResult(true);
    }

    private sealed class ConflictOnUpdateInvitationRepository(IInvitationRepository inner) : IInvitationRepository
    {
        public Task CreateInvitationAsync(UserInvitation invitation, CancellationToken cancellationToken = default)
        {
            return inner.CreateInvitationAsync(invitation, cancellationToken);
        }

        public Task<UserInvitation?> GetInvitationByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default)
        {
            return inner.GetInvitationByTokenHashAsync(tokenHash, cancellationToken);
        }

        public Task<bool> UpdateInvitationAsync(UserInvitation invitation, string expectedVersion, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(false);
        }

        public Task<int> RevokeInvitationsByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default)
        {
            return inner.RevokeInvitationsByEmailAsync(email, tenantId, cancellationToken);
        }

        public Task<IReadOnlyList<InvitationAdministrationSummary>> SearchInvitationsAsync(SearchInvitationsRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            return inner.SearchInvitationsAsync(request, now, cancellationToken);
        }

        public Task<InvitationAdministrationSummary?> GetInvitationAsync(InvitationAdministrationLookupRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            return inner.GetInvitationAsync(request, now, cancellationToken);
        }

        public Task<RevokeInvitationAdministrationResult?> RevokeInvitationAsync(RevokeInvitationAdministrationRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            return inner.RevokeInvitationAsync(request, now, cancellationToken);
        }
    }
}
