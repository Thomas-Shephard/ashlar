using Ashlar.Auditing;
using Moq;

namespace Ashlar.Tests.Identity.Features.Invitations;

internal sealed class InvitationAdministrationServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 6, 4, 12, 0, 0, TimeSpan.Zero);
    private static readonly AdminReadTestBoundary ReadBoundary = new(Now);
    private static readonly AdminReadTestBoundary MutationBoundary = new(Now, proofPurpose: IAccountSecurityAdministrationService.ProofPurpose);

    [Test]
    public void ConstructorRejectsNullRepository()
    {
        Assert.Throws<ArgumentNullException>(() => CreateRawService(null!, null!));
    }

    [Test]
    public void ConstructorRequiresDurableAuditComposition()
    {
        var repository = new RecordingInvitationRepository();
        var transactions = new RecordingTransactionProvider();
        var composition = DurableSecurityMutationTestComposition.Create(transactions, participants: [repository]);

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = CreateRawService(repository, null!));
            Assert.Throws<ArgumentNullException>(() => _ = CreateRawService(repository,
                new InvitationAdministrationServiceDependencies(TransactionProvider: transactions)));
            Assert.Throws<ArgumentNullException>(() => _ = CreateRawService(repository,
                new InvitationAdministrationServiceDependencies(SecurityEventSink: composition.Events)));
            Assert.Throws<ArgumentException>(() => _ = CreateRawService(repository,
                new InvitationAdministrationServiceDependencies(SecurityEventSink: new SecurityEventFanOutSink(), TransactionProvider: transactions)));
            Assert.Throws<InvalidOperationException>(() => _ = CreateRawService(repository,
                new InvitationAdministrationServiceDependencies(SecurityEventSink: new SecurityEventFanOutSink(Mock.Of<IPersistentSecurityEventSink>(), transactionProvider: new RecordingTransactionProvider()), TransactionProvider: transactions)));
            Assert.DoesNotThrow(() => _ = CreateRawService(repository,
                new InvitationAdministrationServiceDependencies(SecurityEventSink: composition.Events, TransactionProvider: composition.Transactions)));
        }
    }

    [Test]
    public void ReaderConstructorValidatesRepositoryAndDefaultsClock()
    {
        Assert.Throws<ArgumentNullException>(() => _ = CreateRawReader(null!));
        Assert.DoesNotThrow(() => _ = CreateRawReader(new RecordingInvitationRepository(), null));
    }

    [Test]
    public async Task ConstructorUsesSystemTimeProviderByDefault()
    {
        var repository = new RecordingInvitationRepository();
        var boundary = new AdminReadTestBoundary(TimeProvider.System.GetUtcNow());
        var before = TimeProvider.System.GetUtcNow();
        var result = await new InvitationAdministrationReader(repository, boundary.Sessions, boundary.Authorizer, boundary.Sink)
            .SearchInvitationsAsync(boundary.Actor, new SearchInvitationsRequest { IncludeAllTenants = true });
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
        var service = CreateReader();

        var missingScope = await service.SearchInvitationsAsync(ReadBoundary.Actor, new SearchInvitationsRequest());
        var conflictingScope = await service.SearchInvitationsAsync(ReadBoundary.Actor, new SearchInvitationsRequest { Tenant = TenantContext.Global, IncludeAllTenants = true });
        var badLimit = await service.SearchInvitationsAsync(ReadBoundary.Actor, new SearchInvitationsRequest { IncludeAllTenants = true, Limit = 0 });
        var badOffset = await service.SearchInvitationsAsync(ReadBoundary.Actor, new SearchInvitationsRequest { IncludeAllTenants = true, Offset = -1 });

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
        var tenantId = Guid.NewGuid();
        for (var i = 0; i < 101; i++)
        {
            repository.SearchResults.Add(CreateSummary() with { TenantId = tenantId, DisplayEmail = "admin@example.com" });
        }

        var request = new SearchInvitationsRequest
        {
            Tenant = new TenantContext(tenantId),
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

        var result = await CreateReader(repository).SearchInvitationsAsync(ReadBoundary.Actor, request);

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
        var service = CreateReader();

        var missingScope = await service.GetInvitationAsync(ReadBoundary.Actor, new InvitationAdministrationLookupRequest(Guid.NewGuid()));
        var conflictingScope = await service.GetInvitationAsync(ReadBoundary.Actor, new InvitationAdministrationLookupRequest(Guid.NewGuid(), TenantContext.Global, IncludeAllTenants: true));
        var emptyId = await service.GetInvitationAsync(ReadBoundary.Actor, new InvitationAdministrationLookupRequest(Guid.Empty, TenantContext.Global));

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
        var service = CreateReader(repository);

        var missing = await CreateReader().GetInvitationAsync(ReadBoundary.Actor, new InvitationAdministrationLookupRequest(Guid.NewGuid(), TenantContext.Global));
        var crossTenant = await service.GetInvitationAsync(ReadBoundary.Actor, new InvitationAdministrationLookupRequest(repository.SingleResult.Id, TenantContext.Global));
        var allTenants = await service.GetInvitationAsync(ReadBoundary.Actor, new InvitationAdministrationLookupRequest(repository.SingleResult.Id, IncludeAllTenants: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missing.FailureCode, Is.EqualTo(AshlarFailureCodes.InvitationNotFound));
            Assert.That(crossTenant.FailureCode, Is.EqualTo(AshlarFailureCodes.InvitationNotFound));
            Assert.That(allTenants.Value, Is.EqualTo(repository.SingleResult));
        }
    }

    [Test]
    public async Task ReaderRejectsHostileSearchFiltersAndMismatchedLookupId()
    {
        var tenantId = Guid.NewGuid();
        var tenantMismatch = new RecordingInvitationRepository();
        tenantMismatch.SearchResults.Add(CreateSummary() with { TenantId = Guid.NewGuid(), DisplayEmail = "admin@example.com" });
        var emailMismatch = new RecordingInvitationRepository();
        emailMismatch.SearchResults.Add(CreateSummary() with { TenantId = tenantId, DisplayEmail = "other@example.com" });
        var queryMismatch = new RecordingInvitationRepository();
        queryMismatch.SearchResults.Add(CreateSummary() with { TenantId = tenantId, DisplayEmail = "other@example.com" });
        var lookupId = Guid.NewGuid();

        var wrongTenant = await CreateReader(tenantMismatch).SearchInvitationsAsync(ReadBoundary.Actor,
            new() { Tenant = new TenantContext(tenantId), Email = "admin@example.com" });
        var wrongEmail = await CreateReader(emailMismatch).SearchInvitationsAsync(ReadBoundary.Actor,
            new() { Tenant = new TenantContext(tenantId), Email = "admin@example.com" });
        var wrongQuery = await CreateReader(queryMismatch).SearchInvitationsAsync(ReadBoundary.Actor,
            new() { Tenant = new TenantContext(tenantId), EmailQuery = "admin" });
        var wrongId = await CreateReader(new RecordingInvitationRepository { SingleResult = CreateSummary() with { TenantId = tenantId } })
            .GetInvitationAsync(ReadBoundary.Actor, new(lookupId, new TenantContext(tenantId)));

        Assert.That(new[] { wrongTenant.Succeeded, wrongEmail.Succeeded, wrongQuery.Succeeded, wrongId.Succeeded }, Is.All.False);
    }

    [Test]
    public async Task ReaderAndMutationRejectHostDenialAndAuditActorMismatch()
    {
        var denied = new AdminReadTestBoundary(Now, authorized: false);
        var repository = new RecordingInvitationRepository();
        var deniedReader = new InvitationAdministrationReader(repository, denied.Sessions, denied.Authorizer, denied.Sink, denied.TimeProvider);
        var search = await deniedReader.SearchInvitationsAsync(denied.Actor, new() { IncludeAllTenants = true });
        var lookup = await deniedReader.GetInvitationAsync(denied.Actor, new(Guid.NewGuid(), IncludeAllTenants: true));

        var composition = new DurableSecurityMutationTestComposition(null, repository);
        var deniedMutationBoundary = new AdminReadTestBoundary(Now, authorized: false,
            proofPurpose: IAccountSecurityAdministrationService.ProofPurpose);
        var deniedService = new InvitationAdministrationService(repository,
            new(new StaticTimeProvider(Now), composition.Events, composition.Transactions), deniedMutationBoundary.Sessions,
            deniedMutationBoundary.Authorizer, deniedMutationBoundary.Sink);
        var request = new RevokeInvitationAdministrationRequest(Guid.NewGuid(), IncludeAllTenants: true, Audit: deniedMutationBoundary.Actor.Audit);
        var hostDenied = await deniedService.RevokeInvitationAsync(deniedMutationBoundary.Actor, request);
        var auditMismatch = await CreateService(repository).RevokeInvitationAsync(MutationBoundary.Actor,
            request with { Audit = new AuditContext(Guid.NewGuid()) });
        var missingAuditActor = await CreateService(repository).RevokeInvitationAsync(MutationBoundary.Actor,
            request with { Audit = new AuditContext() });

        Assert.That(new[] { search.Succeeded, lookup.Succeeded, hostDenied.Succeeded, auditMismatch.Succeeded, missingAuditActor.Succeeded }, Is.All.False);
    }

    [Test]
    public async Task ReaderAndMutationRejectProofForWrongPurpose()
    {
        var wrongRead = new AdminReadTestBoundary(Now, proofPurpose: IAccountSecurityAdministrationService.ProofPurpose);
        var reader = new InvitationAdministrationReader(new RecordingInvitationRepository(), wrongRead.Sessions,
            wrongRead.Authorizer, wrongRead.Sink, wrongRead.TimeProvider);
        var read = await reader.SearchInvitationsAsync(wrongRead.Actor, new() { IncludeAllTenants = true });

        var repository = new RecordingInvitationRepository();
        var composition = new DurableSecurityMutationTestComposition(null, repository);
        var mutation = new InvitationAdministrationService(repository,
            new(new StaticTimeProvider(Now), composition.Events, composition.Transactions), ReadBoundary.Sessions,
            ReadBoundary.Authorizer, ReadBoundary.Sink);
        var write = await mutation.RevokeInvitationAsync(ReadBoundary.Actor,
            new(Guid.NewGuid(), IncludeAllTenants: true, Audit: ReadBoundary.Actor.Audit));

        Assert.That(new[] { read.Succeeded, write.Succeeded }, Is.All.False);
    }

    [Test]
    public async Task RevokeInvitationAsyncRequiresAuditMetadataAndValidReason()
    {
        var service = CreateService();

        var noAudit = await service.RevokeInvitationAsync(MutationBoundary.Actor, new RevokeInvitationAdministrationRequest(Guid.NewGuid(), TenantContext.Global));
        var emptyId = await service.RevokeInvitationAsync(MutationBoundary.Actor, new RevokeInvitationAdministrationRequest(Guid.Empty, TenantContext.Global, Audit: CreateAudit()));
        var longReason = await service.RevokeInvitationAsync(MutationBoundary.Actor, new RevokeInvitationAdministrationRequest(Guid.NewGuid(), TenantContext.Global, Audit: CreateAudit(), Reason: new string('x', 513)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(noAudit.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(emptyId.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(longReason.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public async Task RevokeInvitationAsyncDurablyAuditsTerminalStatus()
    {
        var invitationId = Guid.NewGuid();
        var repository = new RecordingInvitationRepository
        {
            RevokeResult = new RevokeInvitationAdministrationResult(invitationId, null, InvitationAdministrationRevocationStatus.AlreadyAccepted, InvitationAdministrationStatus.Accepted, null)
        };

        var events = new RecordingSecurityEventSink();
        var result = await CreateService(repository, events).RevokeInvitationAsync(MutationBoundary.Actor, new RevokeInvitationAdministrationRequest(invitationId, TenantContext.Global, Audit: CreateAudit(), Reason: "operator request"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.RevocationStatus, Is.EqualTo(InvitationAdministrationRevocationStatus.AlreadyAccepted));
            Assert.That(result.Value?.Status, Is.EqualTo(InvitationAdministrationStatus.Accepted));
            Assert.That(repository.LastRevokeRequest?.InvitationId, Is.EqualTo(invitationId));
            Assert.That(repository.LastRevokeNow, Is.EqualTo(Now));
            Assert.That(events.Events, Has.Count.EqualTo(1));
            Assert.That(events.Events[0].Outcome, Is.EqualTo(SecurityEventOutcomes.Failure));
            Assert.That(events.Events[0].Properties?["revocation_status"], Is.EqualTo(InvitationAdministrationRevocationStatus.AlreadyAccepted.ToString()));
        }
    }

    [Test]
    public async Task RevokeInvitationAsyncMapsMissingInvitationSafely()
    {
        var result = await CreateService().RevokeInvitationAsync(MutationBoundary.Actor, new RevokeInvitationAdministrationRequest(Guid.NewGuid(), TenantContext.Global, Audit: CreateAudit()));

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

        await CreateService(repository, events).RevokeInvitationAsync(MutationBoundary.Actor, new RevokeInvitationAdministrationRequest(invitationId, new TenantContext(tenantId), Audit: CreateAudit()));

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

        await CreateService(repository, events).RevokeInvitationAsync(MutationBoundary.Actor, new RevokeInvitationAdministrationRequest(invitationId, TenantContext.Global, Audit: CreateAudit(), Reason: "cleanup"));

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

        await CreateService(repository, events).RevokeInvitationAsync(MutationBoundary.Actor, new RevokeInvitationAdministrationRequest(invitationId, IncludeAllTenants: true, Audit: CreateAudit()));

        var securityEvent = events.Events.Single();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(securityEvent.TenantId, Is.EqualTo(tenantId));
            Assert.That(securityEvent.Properties?["tenant_scope"], Is.EqualTo("all"));
            Assert.That(securityEvent.Properties?["tenant_id"], Is.EqualTo(tenantId.ToString()));
        }
    }

    [Test]
    public async Task RevokeInvitationAsyncShouldCommitWhenTransactionProviderIsConfigured()
    {
        var transactionProvider = new RecordingTransactionProvider();
        var invitationId = Guid.NewGuid();
        var repository = new RecordingInvitationRepository
        {
            RevokeResult = new RevokeInvitationAdministrationResult(invitationId, null, InvitationAdministrationRevocationStatus.Revoked, InvitationAdministrationStatus.Revoked, Now)
        };

        var result = await CreateService(repository, transactionProvider: transactionProvider)
            .RevokeInvitationAsync(MutationBoundary.Actor, new RevokeInvitationAdministrationRequest(invitationId, TenantContext.Global, Audit: CreateAudit()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(transactionProvider.Transaction.BeginCount, Is.EqualTo(1));
            Assert.That(transactionProvider.Transaction.CommitCount, Is.EqualTo(1));
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

    private static InvitationAdministrationReader CreateRawReader(IInvitationRepository repository, TimeProvider? timeProvider = null) =>
        new(repository, ReadBoundary.Sessions, ReadBoundary.Authorizer, ReadBoundary.Sink, timeProvider);

    private static InvitationAdministrationService CreateRawService(IInvitationRepository repository, InvitationAdministrationServiceDependencies dependencies) =>
        new(repository, dependencies, MutationBoundary.Sessions, MutationBoundary.Authorizer, MutationBoundary.Sink);

    private static InvitationAdministrationReader CreateReader(RecordingInvitationRepository? repository = null) =>
        new(repository ?? new RecordingInvitationRepository(), ReadBoundary.Sessions, ReadBoundary.Authorizer, ReadBoundary.Sink, new StaticTimeProvider(Now));

    private static InvitationAdministrationService CreateService(
        RecordingInvitationRepository? repository = null,
        ISecurityEventSink? events = null,
        RecordingTransactionProvider? transactionProvider = null)
    {
        repository ??= new RecordingInvitationRepository();
        var composition = transactionProvider is null
            ? new DurableSecurityMutationTestComposition(events, repository)
            : DurableSecurityMutationTestComposition.Create(transactionProvider, events, repository);
        return CreateRawService(
            repository,
            new InvitationAdministrationServiceDependencies(new StaticTimeProvider(Now), composition.Events, composition.Transactions));
    }

    private static InvitationAdministrationSummary CreateSummary()
    {
        return new InvitationAdministrationSummary(Guid.NewGuid(), "invite@example.com", null, InvitationAdministrationStatus.Pending, Now, Now, Now.AddDays(1), null, null);
    }

    private static InvitationAdministrationSummary CreateSingleResult()
    {
        var summary = CreateSummary();
        return new InvitationAdministrationSummary(summary.Id, summary.DisplayEmail, summary.TenantId, summary.Status, summary.CreatedAt, summary.UpdatedAt, summary.ExpiresAt, summary.AcceptedAt, summary.RevokedAt);
    }

    private static AuditContext CreateAudit()
    {
        return MutationBoundary.Actor.Audit with { IpAddress = "127.0.0.1" };
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
