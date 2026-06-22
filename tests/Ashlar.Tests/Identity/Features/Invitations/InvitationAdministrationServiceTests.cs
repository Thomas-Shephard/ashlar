using Ashlar.Auditing;

namespace Ashlar.Tests.Identity.Features.Invitations;

internal sealed class InvitationAdministrationServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 6, 4, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public void ConstructorRejectsNullRepository()
    {
        Assert.Throws<ArgumentNullException>(() => new InvitationAdministrationService(null!));
    }

    [Test]
    public async Task ConstructorUsesSystemTimeProviderByDefault()
    {
        var repository = new RecordingInvitationRepository();
        var before = TimeProvider.System.GetUtcNow();
        var result = await new InvitationAdministrationService(repository).SearchInvitationsAsync(new SearchInvitationsRequest { IncludeAllTenants = true });
        var after = TimeProvider.System.GetUtcNow();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(repository.LastSearchNow, Is.GreaterThanOrEqualTo(before));
            Assert.That(repository.LastSearchNow, Is.LessThanOrEqualTo(after));
        }
    }

    [Test]
    public async Task SearchInvitationsAsyncValidatesScopeAndPaging()
    {
        var service = CreateService();

        var missingScope = await service.SearchInvitationsAsync(new SearchInvitationsRequest());
        var conflictingScope = await service.SearchInvitationsAsync(new SearchInvitationsRequest { Tenant = TenantContext.Global, IncludeAllTenants = true });
        var badLimit = await service.SearchInvitationsAsync(new SearchInvitationsRequest { IncludeAllTenants = true, Limit = 0 });
        var badOffset = await service.SearchInvitationsAsync(new SearchInvitationsRequest { IncludeAllTenants = true, Offset = -1 });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missingScope.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(conflictingScope.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(badLimit.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(badOffset.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public async Task SearchInvitationsAsyncCapsLimitAndDelegatesFilters()
    {
        var repository = new RecordingInvitationRepository();
        for (var i = 0; i < 101; i++)
        {
            repository.SearchResults.Add(CreateSummary());
        }

        var request = new SearchInvitationsRequest
        {
            Tenant = new TenantContext(Guid.NewGuid()),
            EmailQuery = "admin",
            Email = "admin@example.com",
            Status = InvitationAdministrationStatus.Pending,
            CreatedFrom = Now.AddDays(-5),
            CreatedTo = Now.AddDays(-4),
            AcceptedFrom = Now.AddDays(-3),
            AcceptedTo = Now.AddDays(-2),
            RevokedFrom = Now.AddDays(-1),
            RevokedTo = Now,
            ExpiresFrom = Now.AddDays(1),
            ExpiresTo = Now.AddDays(2),
            Limit = 500,
            Offset = 7
        };

        var result = await CreateService(repository).SearchInvitationsAsync(request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.Items, Has.Count.EqualTo(100));
            Assert.That(result.Value?.HasMore, Is.True);
            Assert.That(result.Value?.Limit, Is.EqualTo(100));
            Assert.That(result.Value?.Offset, Is.EqualTo(7));
            Assert.That(repository.LastSearchRequest?.Limit, Is.EqualTo(101));
            Assert.That(repository.LastSearchRequest?.EmailQuery, Is.EqualTo(request.EmailQuery));
            Assert.That(repository.LastSearchRequest?.Email, Is.EqualTo(request.Email));
            Assert.That(repository.LastSearchRequest?.Status, Is.EqualTo(request.Status));
            Assert.That(repository.LastSearchNow, Is.EqualTo(Now));
        }
    }

    [Test]
    public async Task GetInvitationAsyncValidatesScopeAndId()
    {
        var service = CreateService();

        var missingScope = await service.GetInvitationAsync(new InvitationAdministrationLookupRequest(Guid.NewGuid()));
        var conflictingScope = await service.GetInvitationAsync(new InvitationAdministrationLookupRequest(Guid.NewGuid(), TenantContext.Global, IncludeAllTenants: true));
        var emptyId = await service.GetInvitationAsync(new InvitationAdministrationLookupRequest(Guid.Empty, TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missingScope.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(conflictingScope.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(emptyId.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public async Task GetInvitationAsyncReturnsSafeNotFoundForMissingOrCrossTenantRows()
    {
        var tenantId = Guid.NewGuid();
        var repository = new RecordingInvitationRepository { SingleResult = CreateSingleResult() with { TenantId = tenantId } };
        var service = CreateService(repository);

        var missing = await CreateService().GetInvitationAsync(new InvitationAdministrationLookupRequest(Guid.NewGuid(), TenantContext.Global));
        var crossTenant = await service.GetInvitationAsync(new InvitationAdministrationLookupRequest(repository.SingleResult.Id, TenantContext.Global));
        var allTenants = await service.GetInvitationAsync(new InvitationAdministrationLookupRequest(repository.SingleResult.Id, IncludeAllTenants: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missing.FailureCode, Is.EqualTo(AshlarFailureCodes.InvitationNotFound));
            Assert.That(crossTenant.FailureCode, Is.EqualTo(AshlarFailureCodes.InvitationNotFound));
            Assert.That(allTenants.Value, Is.EqualTo(repository.SingleResult));
        }
    }

    [Test]
    public async Task RevokeInvitationAsyncRequiresAuditMetadataAndValidReason()
    {
        var service = CreateService();

        var noAudit = await service.RevokeInvitationAsync(new RevokeInvitationAdministrationRequest(Guid.NewGuid(), TenantContext.Global));
        var emptyId = await service.RevokeInvitationAsync(new RevokeInvitationAdministrationRequest(Guid.Empty, TenantContext.Global, Audit: CreateAudit()));
        var longReason = await service.RevokeInvitationAsync(new RevokeInvitationAdministrationRequest(Guid.NewGuid(), TenantContext.Global, Audit: CreateAudit(), Reason: new string('x', 513)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(noAudit.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(emptyId.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(longReason.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public async Task RevokeInvitationAsyncReturnsTerminalStatusWithoutAuditEvent()
    {
        var invitationId = Guid.NewGuid();
        var repository = new RecordingInvitationRepository
        {
            RevokeResult = new RevokeInvitationAdministrationResult(invitationId, null, InvitationAdministrationRevocationStatus.AlreadyAccepted, InvitationAdministrationStatus.Accepted, null)
        };

        var events = new RecordingSecurityEventSink();
        var result = await CreateService(repository, events).RevokeInvitationAsync(new RevokeInvitationAdministrationRequest(invitationId, TenantContext.Global, Audit: CreateAudit(), Reason: "operator request"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.RevocationStatus, Is.EqualTo(InvitationAdministrationRevocationStatus.AlreadyAccepted));
            Assert.That(result.Value?.Status, Is.EqualTo(InvitationAdministrationStatus.Accepted));
            Assert.That(repository.LastRevokeRequest?.InvitationId, Is.EqualTo(invitationId));
            Assert.That(repository.LastRevokeNow, Is.EqualTo(Now));
            Assert.That(events.Events, Is.Empty);
        }
    }

    [Test]
    public async Task RevokeInvitationAsyncMapsMissingInvitationSafely()
    {
        var result = await CreateService().RevokeInvitationAsync(new RevokeInvitationAdministrationRequest(Guid.NewGuid(), TenantContext.Global, Audit: CreateAudit()));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvitationNotFound));
    }

    [Test]
    public async Task RevokeInvitationAsyncRecordsTenantScopedAuditProperties()
    {
        var invitationId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var events = new RecordingSecurityEventSink();
        var repository = new RecordingInvitationRepository
        {
            RevokeResult = new RevokeInvitationAdministrationResult(invitationId, tenantId, InvitationAdministrationRevocationStatus.Revoked, InvitationAdministrationStatus.Revoked, Now)
        };

        await CreateService(repository, events).RevokeInvitationAsync(new RevokeInvitationAdministrationRequest(invitationId, new TenantContext(tenantId), Audit: CreateAudit()));

        var securityEvent = events.Events.Single();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(securityEvent.TenantId, Is.EqualTo(tenantId));
            Assert.That(securityEvent.Properties?["tenant_scope"], Is.EqualTo("tenant"));
            Assert.That(securityEvent.Properties?["tenant_id"], Is.EqualTo(tenantId.ToString()));
            Assert.That(securityEvent.Properties?.ContainsKey("reason"), Is.False);
        }
    }

    [Test]
    public async Task RevokeInvitationAsyncRecordsGlobalAuditPropertiesWithReason()
    {
        var invitationId = Guid.NewGuid();
        var events = new RecordingSecurityEventSink();
        var repository = new RecordingInvitationRepository
        {
            RevokeResult = new RevokeInvitationAdministrationResult(invitationId, null, InvitationAdministrationRevocationStatus.Revoked, InvitationAdministrationStatus.Revoked, Now)
        };

        await CreateService(repository, events).RevokeInvitationAsync(new RevokeInvitationAdministrationRequest(invitationId, TenantContext.Global, Audit: CreateAudit(), Reason: "cleanup"));

        var securityEvent = events.Events.Single();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(securityEvent.TenantId, Is.Null);
            Assert.That(securityEvent.Properties?["tenant_scope"], Is.EqualTo("global"));
            Assert.That(securityEvent.Properties?["reason"], Is.EqualTo("cleanup"));
            Assert.That(securityEvent.Properties?.ContainsKey("tenant_id"), Is.False);
        }
    }

    [Test]
    public async Task RevokeInvitationAsyncRecordsAllTenantAuditScopeWithInvitationTenantId()
    {
        var invitationId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var events = new RecordingSecurityEventSink();
        var repository = new RecordingInvitationRepository
        {
            RevokeResult = new RevokeInvitationAdministrationResult(invitationId, tenantId, InvitationAdministrationRevocationStatus.Revoked, InvitationAdministrationStatus.Revoked, Now)
        };

        await CreateService(repository, events).RevokeInvitationAsync(new RevokeInvitationAdministrationRequest(invitationId, IncludeAllTenants: true, Audit: CreateAudit()));

        var securityEvent = events.Events.Single();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(securityEvent.TenantId, Is.EqualTo(tenantId));
            Assert.That(securityEvent.Properties?["tenant_scope"], Is.EqualTo("all"));
            Assert.That(securityEvent.Properties?["tenant_id"], Is.EqualTo(tenantId.ToString()));
        }
    }

    [Test]
    public void AdministrationModelsDoNotExposeInvitationSecrets()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(typeof(InvitationAdministrationSummary).GetProperties().Select(static property => property.Name), Does.Not.Contain("TokenHash"));
            Assert.That(typeof(InvitationAdministrationSummary).GetProperties().Select(static property => property.Name), Does.Not.Contain("Token"));
            Assert.That(typeof(InvitationAdministrationSummary).GetProperties().Select(static property => property.Name), Does.Not.Contain("Version"));
            Assert.That(typeof(InvitationAdministrationSummary).GetProperties().Select(static property => property.Name), Does.Not.Contain("Metadata"));
        }
    }

    private static InvitationAdministrationService CreateService(RecordingInvitationRepository? repository = null, ISecurityEventSink? events = null)
    {
        return new InvitationAdministrationService(
            repository ?? new RecordingInvitationRepository(),
            new InvitationAdministrationServiceDependencies(new StaticTimeProvider(Now), events));
    }

    private static InvitationAdministrationSummary CreateSummary()
    {
        return new InvitationAdministrationSummary(Guid.NewGuid(), "invite@example.com", null, InvitationAdministrationStatus.Pending, Now, Now, Now.AddDays(1), null, null);
    }

    private static InvitationAdministrationSummary CreateSingleResult()
    {
        var summary = CreateSummary();
        return new InvitationAdministrationSummary(summary.Id, summary.Email, summary.TenantId, summary.Status, summary.CreatedAt, summary.UpdatedAt, summary.ExpiresAt, summary.AcceptedAt, summary.RevokedAt);
    }

    private static AuditContext CreateAudit()
    {
        return new AuditContext(Guid.NewGuid(), "127.0.0.1");
    }

    private sealed class RecordingInvitationRepository : IInvitationRepository
    {
        public List<InvitationAdministrationSummary> SearchResults { get; } = [];
        public SearchInvitationsRequest? LastSearchRequest { get; private set; }
        public DateTimeOffset? LastSearchNow { get; private set; }
        public InvitationAdministrationSummary? SingleResult { get; init; }
        public RevokeInvitationAdministrationRequest? LastRevokeRequest { get; private set; }
        public DateTimeOffset? LastRevokeNow { get; private set; }
        public RevokeInvitationAdministrationResult? RevokeResult { get; init; }

        public Task CreateInvitationAsync(UserInvitation invitation, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<UserInvitation?> GetInvitationByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<bool> UpdateInvitationAsync(UserInvitation invitation, string expectedVersion, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<int> RevokeInvitationsByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task<IReadOnlyList<InvitationAdministrationSummary>> SearchInvitationsAsync(SearchInvitationsRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            LastSearchRequest = request;
            LastSearchNow = now;
            return Task.FromResult<IReadOnlyList<InvitationAdministrationSummary>>(SearchResults.AsReadOnly());
        }

        public Task<InvitationAdministrationSummary?> GetInvitationAsync(InvitationAdministrationLookupRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(SingleResult);
        }

        public Task<RevokeInvitationAdministrationResult?> RevokeInvitationAsync(RevokeInvitationAdministrationRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            LastRevokeRequest = request;
            LastRevokeNow = now;
            return Task.FromResult(RevokeResult);
        }
    }

    private sealed class RecordingSecurityEventSink : ISecurityEventSink
    {
        public List<AshlarSecurityEvent> Events { get; } = [];

        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            Events.Add(securityEvent);
            return Task.CompletedTask;
        }
    }

    private sealed class StaticTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
