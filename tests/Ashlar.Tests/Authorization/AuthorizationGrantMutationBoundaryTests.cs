using Ashlar.Auditing;
using Ashlar.Authorization;
using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Tests.Authorization;

internal sealed class AuthorizationGrantMutationBoundaryTests
{
    private readonly FakeTimeProvider _clock = new(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
    private readonly Dictionary<Guid, AuthenticationSession> _sessions = [];

    [Test]
    public void PublicRequestsRejectMissingActorAndAudit()
    {
        var audit = new AuditContext(Guid.NewGuid());
        Assert.Throws<ArgumentNullException>(() => new CreateAuthorizationGrantRequest(Guid.NewGuid(), null!, audit, TenantContext.Global, permission: "read"));
        Assert.Throws<ArgumentNullException>(() => new RevokeAuthorizationGrantRequest(Guid.NewGuid(), null!, audit, TenantContext.Global));
        Assert.Throws<ArgumentNullException>(() => new CreateAuthorizationGrantRequest(Guid.NewGuid(), Actor(), null!, TenantContext.Global, permission: "read"));
    }

    [Test]
    public async Task CreateAndRevokeRejectAuditActorMismatch()
    {
        var repository = new Repository();
        var service = Service(repository);
        var actor = Actor();
        var mismatchedAudit = new AuditContext(Guid.NewGuid());

        var create = await service.CreateGrantAsync(new CreateAuthorizationGrantRequest(Guid.NewGuid(), actor, mismatchedAudit, TenantContext.Global, permission: "read"));
        var revoke = await service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(Guid.NewGuid(), actor, mismatchedAudit, TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(create.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(revoke.Status, Is.EqualTo(AuthorizationGrantRevocationStatus.ValidationFailed));
            Assert.That(repository.Grants, Is.Empty);
        }
    }

    [Test]
    public async Task CreateRejectsMissingAuditActorIdentity()
    {
        var repository = new Repository();
        var actor = Actor();

        var result = await Service(repository).CreateGrantAsync(new CreateAuthorizationGrantRequest(
            Guid.NewGuid(), actor, new AuditContext(), TenantContext.Global, permission: "read"));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
    }

    [TestCase("wrong-purpose", 1)]
    [TestCase(AuthorizationGrantService.AdministrationProofPurpose, -1)]
    public async Task CreateRejectsWrongPurposeOrStaleProof(string purpose, int expiryMinutes)
    {
        var repository = new Repository();
        var actor = Actor(purpose, expiryMinutes);
        var result = await Service(repository).CreateGrantAsync(new CreateAuthorizationGrantRequest(
            Guid.NewGuid(), actor, actor.Audit, TenantContext.Global, permission: "read"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(repository.Grants, Is.Empty);
        }
    }

    [TestCase("wrong-purpose", 1)]
    [TestCase(AuthorizationGrantService.AdministrationProofPurpose, -1)]
    public async Task RevokeRejectsWrongPurposeOrStaleProof(string purpose, int expiryMinutes)
    {
        var repository = new Repository();
        var grant = new AuthorizationGrant
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            Permission = "read",
            CreatedAt = _clock.GetUtcNow()
        };
        repository.Grants.Add(grant);
        var actor = Actor(purpose, expiryMinutes);

        var result = await Service(repository).RevokeGrantAsync(new RevokeAuthorizationGrantRequest(
            grant.Id, actor, actor.Audit, TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AuthorizationGrantRevocationStatus.ValidationFailed));
            Assert.That(grant.RevokedAt, Is.Null);
        }
    }

    [Test]
    public async Task CreateRejectsProofFromRevokedSession()
    {
        var repository = new Repository();
        var actor = Actor();
        _sessions[actor.CurrentSessionId].RevokedAt = _clock.GetUtcNow();

        var result = await Service(repository).CreateGrantAsync(new CreateAuthorizationGrantRequest(
            Guid.NewGuid(), actor, actor.Audit, TenantContext.Global, permission: "read"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            Assert.That(repository.Grants, Is.Empty);
        }
    }

    [TestCase("missing")]
    [TestCase("user")]
    [TestCase("tenant")]
    public async Task CreateRejectsMissingOrMismatchedActiveSession(string mismatch)
    {
        var repository = new Repository();
        var actor = Actor();
        var session = _sessions[actor.CurrentSessionId];
        if (mismatch == "missing")
        {
            _sessions.Remove(actor.CurrentSessionId);
        }
        else
        {
            _sessions[actor.CurrentSessionId] = new AuthenticationSession
            {
                Id = session.Id,
                UserId = mismatch == "user" ? Guid.NewGuid() : session.UserId,
                TenantId = mismatch == "tenant" ? Guid.NewGuid() : session.TenantId,
                TokenHash = session.TokenHash,
                CreatedAt = session.CreatedAt,
                ExpiresAt = session.ExpiresAt
            };
        }

        var result = await Service(repository).CreateGrantAsync(new CreateAuthorizationGrantRequest(
            Guid.NewGuid(), actor, actor.Audit, TenantContext.Global, permission: "read"));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
    }

    [Test]
    public async Task CreateRejectsMissingSessionRepositoryOrAuthorizer()
    {
        var repository = new Repository();
        var actor = Actor();
        var request = new CreateAuthorizationGrantRequest(Guid.NewGuid(), actor, actor.Audit, TenantContext.Global, permission: "read");

        var missingSessions = await Service(repository, includeSessionRepository: false).CreateGrantAsync(request);
        var missingAuthorizer = await Service(repository, includeAuthorizer: false).CreateGrantAsync(request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missingSessions.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(missingAuthorizer.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public async Task CreateAndRevokeRejectAllTenantScope()
    {
        var repository = new Repository();
        var actor = Actor();
        var service = Service(repository);

        var create = await service.CreateGrantAsync(new CreateAuthorizationGrantRequest(Guid.NewGuid(), actor, actor.Audit, includeAllTenants: true, permission: "read"));
        var revoke = await service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(Guid.NewGuid(), actor, actor.Audit, includeAllTenants: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(create.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(revoke.Status, Is.EqualTo(AuthorizationGrantRevocationStatus.ValidationFailed));
        }
    }

    [Test]
    public async Task CreateAndRevokeRejectActorTargetTenantMismatch()
    {
        var repository = new Repository();
        var actorTenant = new TenantContext(Guid.NewGuid());
        var targetTenant = new TenantContext(Guid.NewGuid());
        var actor = Actor(tenant: actorTenant);
        var userId = Guid.NewGuid();
        repository.Users[userId] = new User { Id = userId, DisplayEmail = "target@example.test", TenantId = targetTenant.TenantId };
        var grant = new AuthorizationGrant { Id = Guid.NewGuid(), UserId = userId, TenantId = targetTenant.TenantId, Permission = "read", CreatedAt = _clock.GetUtcNow() };
        repository.Grants.Add(grant);
        var service = Service(repository, authorizer: new SameTenantAuthorizer());

        var create = await service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, actor, actor.Audit, targetTenant, permission: "write"));
        var revoke = await service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(grant.Id, actor, actor.Audit, targetTenant));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(create.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(revoke.Status, Is.EqualTo(AuthorizationGrantRevocationStatus.NotFound));
            Assert.That(repository.Grants, Has.Count.EqualTo(1));
            Assert.That(grant.RevokedAt, Is.Null);
        }
    }

    [Test]
    public async Task ValidActorBoundCreateAndRevokeAuditActor()
    {
        var repository = new Repository();
        var events = new Sink();
        var actor = Actor();
        var userId = Guid.NewGuid();
        repository.Users[userId] = new User { Id = userId, DisplayEmail = "target@example.test" };
        var service = Service(repository, events);

        var created = await service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, actor, actor.Audit, TenantContext.Global, permission: "read"));
        var revoked = await service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(created.Value!.Id, actor, actor.Audit, TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(created.Succeeded, Is.True);
            Assert.That(revoked.Status, Is.EqualTo(AuthorizationGrantRevocationStatus.Revoked));
            Assert.That(events.Events, Has.Count.EqualTo(2));
            Assert.That(events.Events.All(e => e.ActorUserId == actor.ActorUserId), Is.True);
        }
    }

    private AccountSecurityActorContext Actor(string purpose = AuthorizationGrantService.AdministrationProofPurpose, int expiryMinutes = 5, TenantContext? tenant = null)
    {
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var audit = new AuditContext(userId, CorrelationId: "grant-boundary-test");
        tenant ??= TenantContext.Global;
        var proof = new FreshMfaVerificationProof(userId, tenant.TenantId, sessionId, _clock.GetUtcNow(), _clock.GetUtcNow().AddMinutes(expiryMinutes), purpose);
        _sessions[sessionId] = new AuthenticationSession
        {
            Id = sessionId,
            UserId = userId,
            TenantId = tenant.TenantId,
            TokenHash = "test",
            CreatedAt = _clock.GetUtcNow(),
            ExpiresAt = _clock.GetUtcNow().AddHours(1)
        };
        return new AccountSecurityActorContext(userId, tenant, sessionId, proof, audit);
    }

    private AuthorizationGrantService Service(Repository repository, ISecurityEventSink? sink = null,
        IAccountSecurityOperationAuthorizer? authorizer = null, bool includeSessionRepository = true, bool includeAuthorizer = true)
    {
        var sessions = new Mock<IAuthenticationSessionRepository>();
        sessions.Setup(x => x.GetSessionAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Guid id, CancellationToken _) => _sessions.GetValueOrDefault(id));
        return new(repository, repository, timeProvider: _clock, securityEventSink: sink,
            mutationContext: new AuthorizationGrantMutationContext(
                includeAuthorizer ? authorizer ?? new AllowAuthorizer() : null,
                includeSessionRepository ? sessions.Object : null));
    }

    private sealed class AllowAuthorizer : IAccountSecurityOperationAuthorizer
    {
        public ValueTask<bool> AuthorizeAsync(AccountSecurityAuthorizationContext context, CancellationToken cancellationToken = default) => ValueTask.FromResult(true);
    }

    private sealed class SameTenantAuthorizer : IAccountSecurityOperationAuthorizer
    {
        public ValueTask<bool> AuthorizeAsync(AccountSecurityAuthorizationContext context, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(context.ActorTenant.TenantId == context.TargetTenant?.TenantId);
    }

    private sealed class Sink : ISecurityEventSink
    {
        public List<AshlarSecurityEvent> Events { get; } = [];
        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default) { Events.Add(securityEvent); return Task.CompletedTask; }
    }

    private sealed class Repository : IAuthorizationGrantRepository, IUserRepository
    {
        public List<AuthorizationGrant> Grants { get; } = [];
        public Dictionary<Guid, User> Users { get; } = [];
        public Task CreateGrantAsync(AuthorizationGrant grant, CancellationToken cancellationToken = default) { Grants.Add(grant); return Task.CompletedTask; }
        public Task<IReadOnlyList<AuthorizationGrant>> ListGrantsAsync(ListAuthorizationGrantsRequest request, CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<AuthorizationGrant>>(Grants);
        public Task<AuthorizationGrant?> GetGrantAsync(Guid grantId, Guid? tenantId, CancellationToken cancellationToken = default) => Task.FromResult(Grants.SingleOrDefault(g => g.Id == grantId && g.TenantId == tenantId));
        public Task<bool> RevokeGrantAsync(Guid grantId, Guid? tenantId, DateTimeOffset revokedAt, CancellationToken cancellationToken = default) { var grant = Grants.SingleOrDefault(g => g.Id == grantId && g.TenantId == tenantId); if (grant is null) return Task.FromResult(false); grant.RevokedAt = revokedAt; return Task.FromResult(true); }
        public Task<IUser?> GetUserByIdAsync(Guid userId, CancellationToken cancellationToken = default) => Task.FromResult<IUser?>(Users.GetValueOrDefault(userId));
        public Task<IUser?> GetUserByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default) => Task.FromResult<IUser?>(null);
        public Task<IUser?> GetUserByProviderKeyAsync(ProviderType type, string providerName, string providerKey, CancellationToken cancellationToken = default) => Task.FromResult<IUser?>(null);
        public Task CreateUserAsync(IUser user, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task UpdateUserAsync(IUser user, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
