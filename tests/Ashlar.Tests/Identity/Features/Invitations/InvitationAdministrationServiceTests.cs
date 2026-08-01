using Ashlar.Auditing;
using Moq;

namespace Ashlar.Tests.Identity.Features.Invitations;

internal sealed class InvitationAdministrationServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 6, 4, 12, 0, 0, TimeSpan.Zero);
    private static readonly AdminReadTestBoundary ReadBoundary = new(Now);
    private static readonly AdminReadTestBoundary MutationBoundary = new(Now, proofPurpose: IInvitationAdministrationService.RevokeProofPurpose);

    [Test]
    public void ConstructorRejectsNullRepository()
    {
        Assert.Throws<ArgumentNullException>(() => CreateRawService(null!, null!));
        Assert.Throws<ArgumentNullException>(() => new InvitationAdministrationService(
            new RecordingInvitationRepository(), null!, null!, MutationBoundary.Sessions,
            MutationBoundary.Authorizer, MutationBoundary.Sink));
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
        var boundary = new AdminReadTestBoundary(Now);
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

        var result = await new InvitationAdministrationReader(repository, boundary.Sessions, boundary.Authorizer, boundary.Sink, boundary.TimeProvider)
            .SearchInvitationsAsync(boundary.Actor, request);

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
            Assert.That(boundary.Sink.Events.Single().Outcome, Is.EqualTo(SecurityEventOutcomes.Success));
            Assert.That(boundary.Sink.Events.Single().Properties!["operation"], Is.EqualTo(nameof(AccountSecurityOperation.SearchInvitations)));
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
        var boundary = new AdminReadTestBoundary(Now);
        InvitationAdministrationReader Reader(RecordingInvitationRepository value) =>
            new(value, boundary.Sessions, boundary.Authorizer, boundary.Sink, boundary.TimeProvider);

        var missing = await Reader(new()).GetInvitationAsync(boundary.Actor, new InvitationAdministrationLookupRequest(Guid.NewGuid(), TenantContext.Global));
        var crossTenant = await Reader(repository).GetInvitationAsync(boundary.Actor, new InvitationAdministrationLookupRequest(repository.SingleResult.Id, TenantContext.Global));
        var allTenants = await Reader(repository).GetInvitationAsync(boundary.Actor, new InvitationAdministrationLookupRequest(repository.SingleResult.Id, IncludeAllTenants: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missing.FailureCode, Is.EqualTo(AshlarFailureCodes.InvitationNotFound));
            Assert.That(crossTenant.FailureCode, Is.EqualTo(AshlarFailureCodes.InvitationNotFound));
            Assert.That(allTenants.Value, Is.EqualTo(repository.SingleResult));
            Assert.That(boundary.Sink.Events.Select(item => item.Outcome),
                Is.EqualTo(new[] { SecurityEventOutcomes.Failure, SecurityEventOutcomes.Failure, SecurityEventOutcomes.Success }));
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
        var nullResult = new RecordingInvitationRepository();
        nullResult.SearchResults.Add(null!);
        var nullEmail = new RecordingInvitationRepository();
        nullEmail.SearchResults.Add(CreateSummary() with { TenantId = tenantId, DisplayEmail = null! });
        var lookupId = Guid.NewGuid();
        var boundary = new AdminReadTestBoundary(Now);
        InvitationAdministrationReader Reader(IInvitationRepository repository) =>
            new(repository, boundary.Sessions, boundary.Authorizer, boundary.Sink, boundary.TimeProvider);

        Assert.ThrowsAsync<InvalidOperationException>(() => Reader(tenantMismatch).SearchInvitationsAsync(boundary.Actor,
            new() { Tenant = new TenantContext(tenantId), Email = "admin@example.com" }));
        Assert.ThrowsAsync<InvalidOperationException>(() => Reader(emailMismatch).SearchInvitationsAsync(boundary.Actor,
            new() { Tenant = new TenantContext(tenantId), Email = "admin@example.com" }));
        Assert.ThrowsAsync<InvalidOperationException>(() => Reader(queryMismatch).SearchInvitationsAsync(boundary.Actor,
            new() { Tenant = new TenantContext(tenantId), EmailQuery = "admin" }));
        Assert.ThrowsAsync<InvalidOperationException>(() => Reader(nullResult).SearchInvitationsAsync(boundary.Actor,
            new() { Tenant = new TenantContext(tenantId) }));
        Assert.ThrowsAsync<InvalidOperationException>(() => Reader(nullEmail).SearchInvitationsAsync(boundary.Actor,
            new() { Tenant = new TenantContext(tenantId), EmailQuery = "admin" }));
        var wrongId = await Reader(new RecordingInvitationRepository { SingleResult = CreateSummary() with { TenantId = tenantId } })
            .GetInvitationAsync(boundary.Actor, new(lookupId, new TenantContext(tenantId)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(wrongId.Succeeded, Is.False);
            Assert.That(boundary.Sink.Events, Has.Count.EqualTo(6));
            Assert.That(boundary.Sink.Events.Select(item => item.Outcome), Is.All.EqualTo(SecurityEventOutcomes.Failure));
            Assert.That(boundary.Sink.Events.Take(5).Select(item => item.Properties!["operation"]),
                Is.All.EqualTo(nameof(AccountSecurityOperation.SearchInvitations)));
        }
    }

    [Test]
    public void ReaderRepositoryFailuresAreAuditedAndRethrown()
    {
        var exception = new IOException("provider failed");
        var repository = new Mock<IInvitationRepository>();
        repository.Setup(candidate => candidate.SearchInvitationsAsync(It.IsAny<SearchInvitationsRequest>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ThrowsAsync(exception);
        repository.Setup(candidate => candidate.GetInvitationAsync(It.IsAny<InvitationAdministrationLookupRequest>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ThrowsAsync(exception);
        var boundary = new AdminReadTestBoundary(Now);
        var reader = new InvitationAdministrationReader(repository.Object, boundary.Sessions, boundary.Authorizer, boundary.Sink, boundary.TimeProvider);

        var search = Assert.ThrowsAsync<IOException>(() => reader.SearchInvitationsAsync(boundary.Actor, new() { IncludeAllTenants = true }));
        var lookup = Assert.ThrowsAsync<IOException>(() => reader.GetInvitationAsync(boundary.Actor, new(Guid.NewGuid(), IncludeAllTenants: true)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(search, Is.SameAs(exception));
            Assert.That(lookup, Is.SameAs(exception));
            Assert.That(boundary.Sink.Events, Has.Count.EqualTo(2));
            Assert.That(boundary.Sink.Events.Select(item => item.Outcome), Is.All.EqualTo(SecurityEventOutcomes.Failure));
            Assert.That(boundary.Sink.Events.Select(item => item.Properties!["operation"]),
                Is.EqualTo(new[] { nameof(AccountSecurityOperation.SearchInvitations), nameof(AccountSecurityOperation.ReadInvitation) }));
        }

        repository.Setup(candidate => candidate.SearchInvitationsAsync(It.IsAny<SearchInvitationsRequest>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((IReadOnlyList<InvitationAdministrationSummary>)null!);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(Assert.ThrowsAsync<InvalidOperationException>(() => reader.SearchInvitationsAsync(boundary.Actor, new() { IncludeAllTenants = true })), Is.Not.Null);
            Assert.That(boundary.Sink.Events.Last().Outcome, Is.EqualTo(SecurityEventOutcomes.Failure));
        }

        var results = new Mock<IReadOnlyList<InvitationAdministrationSummary>>();
        results.Setup(candidate => candidate.GetEnumerator()).Throws(exception);
        repository.Setup(candidate => candidate.SearchInvitationsAsync(It.IsAny<SearchInvitationsRequest>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(results.Object);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(Assert.ThrowsAsync<IOException>(() => reader.SearchInvitationsAsync(boundary.Actor, new() { IncludeAllTenants = true })), Is.SameAs(exception));
            Assert.That(boundary.Sink.Events.Last().Outcome, Is.EqualTo(SecurityEventOutcomes.Failure));
        }

        var auditException = new IOException("audit failed");
        var sink = new Mock<IPersistentSecurityEventSink>();
        sink.Setup(candidate => candidate.RecordAsync(It.IsAny<AshlarSecurityEvent>(), It.IsAny<CancellationToken>())).ThrowsAsync(auditException);
        var failClosedReader = new InvitationAdministrationReader(repository.Object, boundary.Sessions, boundary.Authorizer, sink.Object, boundary.TimeProvider);
        Assert.That(Assert.ThrowsAsync<IOException>(() => failClosedReader.SearchInvitationsAsync(boundary.Actor, new() { IncludeAllTenants = true })), Is.SameAs(auditException));
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
            proofPurpose: IInvitationAdministrationService.RevokeProofPurpose);
        var deniedService = new InvitationAdministrationService(repository,
            new(new StaticTimeProvider(Now), composition.Events, composition.Transactions), new RecordingMutationExecutor(), deniedMutationBoundary.Sessions,
            deniedMutationBoundary.Authorizer, deniedMutationBoundary.Sink);
        var request = new RevokeInvitationByIdAdministrationRequest(Guid.NewGuid(), IncludeAllTenants: true);
        var hostDenied = await deniedService.RevokeInvitationByIdAsync(deniedMutationBoundary.Actor, request);
        var mismatchedActor = CopyActorWithAudit(MutationBoundary.Actor, new AuditContext(Guid.NewGuid()));
        var auditMismatch = await CreateService(repository).RevokeInvitationByIdAsync(mismatchedActor, request);
        var missingAuditActor = await CreateService(repository).RevokeInvitationByIdAsync(
            CopyActorWithAudit(MutationBoundary.Actor, new AuditContext()), request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(new[] { search.Succeeded, lookup.Succeeded, hostDenied.Succeeded, auditMismatch.Succeeded, missingAuditActor.Succeeded }, Is.All.False);
            Assert.That(repository.LastSearchRequest, Is.Null);
            Assert.That(repository.GetCalls, Is.Zero);
        }
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
            new(new StaticTimeProvider(Now), composition.Events, composition.Transactions), new RecordingMutationExecutor(), ReadBoundary.Sessions,
            ReadBoundary.Authorizer, ReadBoundary.Sink);
        var write = await mutation.RevokeInvitationByIdAsync(ReadBoundary.Actor,
            new(Guid.NewGuid(), IncludeAllTenants: true));

        Assert.That(new[] { read.Succeeded, write.Succeeded }, Is.All.False);
    }

    [Test]
    public void InvitationMutationsRequireActorAndProof()
    {
        var service = CreateService();
        var invitation = new CreateInvitationAdministrationRequest(
            new CreateInvitationRequest { Email = "invite@example.com" },
            new Uri("https://app.example/join"), TenantContext.Global);

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentNullException>(() => service.CreateInvitationAsync(null!, invitation));
            Assert.ThrowsAsync<ArgumentNullException>(() => service.RevokeInvitationsByEmailAsync(null!,
                new RevokeInvitationsByEmailAdministrationRequest { Email = "invite@example.com", Tenant = TenantContext.Global }));
            Assert.ThrowsAsync<ArgumentNullException>(() => service.RevokeInvitationByIdAsync(null!,
                new RevokeInvitationByIdAdministrationRequest(Guid.NewGuid(), TenantContext.Global)));
            Assert.Throws<ArgumentNullException>(() => new AccountSecurityActorContext(Guid.NewGuid(), TenantContext.Global,
                Guid.NewGuid(), null!, new AuditContext(Guid.NewGuid())));
        }
    }

    [Test]
    public async Task InvitationCreationRequiresMatchingScopeAndSupportsTenantAndGlobal()
    {
        var boundary = new AdminReadTestBoundary(Now, proofPurpose: IInvitationAdministrationService.CreateProofPurpose);
        var mutations = new RecordingMutationExecutor();
        var service = CreateService(boundary, mutations);
        var tenantId = Guid.NewGuid();

        var mismatch = await service.CreateInvitationAsync(boundary.Actor, new(
            new CreateInvitationRequest { Email = "invite@example.com", TenantId = tenantId },
            new Uri("https://app.example/join"), TenantContext.Global));
        var tenant = await service.CreateInvitationAsync(boundary.Actor, new(
            new CreateInvitationRequest { Email = "invite@example.com", TenantId = tenantId },
            new Uri("https://app.example/join"), new TenantContext(tenantId)));
        var global = await service.CreateInvitationAsync(boundary.Actor, new(
            new CreateInvitationRequest { Email = "invite@example.com" },
            new Uri("https://app.example/join"), TenantContext.Global));
        var wrongProof = await CreateService(MutationBoundary, mutations).CreateInvitationAsync(MutationBoundary.Actor, new(
            new CreateInvitationRequest { Email = "invite@example.com" },
            new Uri("https://app.example/join"), TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(mismatch.Succeeded, Is.False);
            Assert.That(tenant.Succeeded, Is.True);
            Assert.That(global.Succeeded, Is.True);
            Assert.That(wrongProof.Succeeded, Is.False);
            Assert.That(mutations.Created, Has.Count.EqualTo(2));
            Assert.That(mutations.LastContext?.UserId, Is.EqualTo(boundary.Actor.ActorUserId));
        }
    }

    [Test]
    public async Task InvitationCreationRejectsInvalidMutationInputBeforeAuthorization()
    {
        var boundary = new AdminReadTestBoundary(Now, proofPurpose: IInvitationAdministrationService.CreateProofPurpose);
        var mutations = new RecordingMutationExecutor { RejectCreation = true };
        var result = await CreateService(boundary, mutations).CreateInvitationAsync(boundary.Actor, new(
            new CreateInvitationRequest { Email = "invite@example.com" },
            new Uri("https://app.example/join"), TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(boundary.AuthorizationContexts, Is.Empty);
            Assert.That(mutations.Created, Is.Empty);
        }
    }

    [Test]
    public async Task InvitationEmailRevocationRejectsInvalidMutationInputBeforeAuthorization()
    {
        var boundary = new AdminReadTestBoundary(Now, proofPurpose: IInvitationAdministrationService.RevokeProofPurpose);
        var mutations = new RecordingMutationExecutor { RejectRevocation = true };
        var result = await CreateService(boundary, mutations).RevokeInvitationsByEmailAsync(boundary.Actor,
            new RevokeInvitationsByEmailAdministrationRequest { Email = "invite@example.com", IncludeAllTenants = true });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(boundary.AuthorizationContexts, Is.Empty);
            Assert.That(mutations.Revoked, Is.Empty);
        }
    }

    [Test]
    public async Task InvitationRevocationRoutesUseDistinctHostOperations()
    {
        var boundary = new AdminReadTestBoundary(Now, proofPurpose: IInvitationAdministrationService.RevokeProofPurpose);
        var service = CreateService(boundary, new RecordingMutationExecutor());

        await service.RevokeInvitationsByEmailAsync(boundary.Actor,
            new RevokeInvitationsByEmailAdministrationRequest { Email = "invite@example.com", IncludeAllTenants = true });
        await service.RevokeInvitationByIdAsync(boundary.Actor,
            new RevokeInvitationByIdAdministrationRequest(Guid.NewGuid(), IncludeAllTenants: true));

        Assert.That(boundary.AuthorizationContexts.Select(static context => context.Operation),
            Is.EqualTo(new[] { AccountSecurityOperation.RevokeInvitationsByEmail, AccountSecurityOperation.RevokeInvitationById }));
    }

    [Test]
    public async Task InvitationEmailRevocationSupportsTenantAndAuthorizedAllTenantScope()
    {
        var mutations = new RecordingMutationExecutor();
        var service = CreateService(MutationBoundary, mutations);
        var tenant = await service.RevokeInvitationsByEmailAsync(MutationBoundary.Actor,
            new RevokeInvitationsByEmailAdministrationRequest { Email = "invite@example.com", Tenant = new TenantContext(Guid.NewGuid()) });
        var all = await service.RevokeInvitationsByEmailAsync(MutationBoundary.Actor,
            new RevokeInvitationsByEmailAdministrationRequest { Email = "invite@example.com", IncludeAllTenants = true });
        mutations.RevokeResult = Result.Failure<RevokeInvitationsByEmailAdministrationResult>(AshlarFailureCodes.ConcurrencyConflict);
        var conflict = await service.RevokeInvitationsByEmailAsync(MutationBoundary.Actor,
            new RevokeInvitationsByEmailAdministrationRequest { Email = "invite@example.com", IncludeAllTenants = true });
        var invalidScope = await service.RevokeInvitationsByEmailAsync(MutationBoundary.Actor,
            new RevokeInvitationsByEmailAdministrationRequest { Email = "invite@example.com" });
        var wrongProof = await CreateService(ReadBoundary, mutations).RevokeInvitationsByEmailAsync(ReadBoundary.Actor,
            new RevokeInvitationsByEmailAdministrationRequest { Email = "invite@example.com", IncludeAllTenants = true });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(tenant.Succeeded, Is.True);
            Assert.That(tenant.Value?.RevokedCount, Is.EqualTo(1));
            Assert.That(all.Succeeded, Is.True);
            Assert.That(conflict.FailureCode, Is.EqualTo(AshlarFailureCodes.ConcurrencyConflict));
            Assert.That(invalidScope.Succeeded, Is.False);
            Assert.That(wrongProof.Succeeded, Is.False);
            Assert.That(mutations.Revoked, Has.Count.EqualTo(3));
            Assert.That(mutations.LastAudit?.ActorUserId, Is.EqualTo(MutationBoundary.Actor.ActorUserId));
            Assert.That(mutations.LastSessionId, Is.EqualTo(MutationBoundary.Actor.CurrentSessionId));
        }
    }

    [Test]
    public async Task NewInvitationMutationsRejectRevokedSessionHostDenialAndAuditMismatch()
    {
        var mutations = new RecordingMutationExecutor();
        var createRequest = new CreateInvitationAdministrationRequest(
            new CreateInvitationRequest { Email = "invite@example.com" },
            new Uri("https://app.example/join"), TenantContext.Global);
        var revokeRequest = new RevokeInvitationsByEmailAdministrationRequest { Email = "invite@example.com", IncludeAllTenants = true };

        var revokedCreate = new AdminReadTestBoundary(Now,
            proofPurpose: IInvitationAdministrationService.CreateProofPurpose, sessionRevoked: true);
        var revokedRevoke = new AdminReadTestBoundary(Now,
            proofPurpose: IInvitationAdministrationService.RevokeProofPurpose, sessionRevoked: true);
        var deniedCreate = new AdminReadTestBoundary(Now, authorized: false,
            proofPurpose: IInvitationAdministrationService.CreateProofPurpose);
        var deniedRevoke = new AdminReadTestBoundary(Now, authorized: false,
            proofPurpose: IInvitationAdministrationService.RevokeProofPurpose);
        var validCreate = new AdminReadTestBoundary(Now,
            proofPurpose: IInvitationAdministrationService.CreateProofPurpose);
        var validRevoke = new AdminReadTestBoundary(Now,
            proofPurpose: IInvitationAdministrationService.RevokeProofPurpose);

        var results = new[]
        {
            await CreateService(revokedCreate, mutations).CreateInvitationAsync(revokedCreate.Actor, createRequest),
            await CreateService(revokedRevoke, mutations).RevokeInvitationsByEmailAsync(revokedRevoke.Actor, revokeRequest),
            await CreateService(deniedCreate, mutations).CreateInvitationAsync(deniedCreate.Actor, createRequest),
            await CreateService(deniedRevoke, mutations).RevokeInvitationsByEmailAsync(deniedRevoke.Actor, revokeRequest),
            await CreateService(validCreate, mutations).CreateInvitationAsync(
                CopyActorWithAudit(validCreate.Actor, new AuditContext(Guid.NewGuid())), createRequest),
            await CreateService(validRevoke, mutations).RevokeInvitationsByEmailAsync(
                CopyActorWithAudit(validRevoke.Actor, new AuditContext(Guid.NewGuid())), revokeRequest)
        };

        using (Assert.EnterMultipleScope())
        {
            Assert.That(results.Select(static result => result.Succeeded), Is.All.False);
            Assert.That(mutations.Created, Is.Empty);
            Assert.That(mutations.Revoked, Is.Empty);
        }
    }

    [Test]
    public async Task RevokeInvitationByIdAsyncRequiresValidIdAndReason()
    {
        var service = CreateService();

        var emptyId = await service.RevokeInvitationByIdAsync(MutationBoundary.Actor, new RevokeInvitationByIdAdministrationRequest(Guid.Empty, TenantContext.Global));
        var longReason = await service.RevokeInvitationByIdAsync(MutationBoundary.Actor, new RevokeInvitationByIdAdministrationRequest(Guid.NewGuid(), TenantContext.Global, Reason: new string('x', 513)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(emptyId.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(longReason.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public async Task RevokeInvitationByIdAsyncDurablyAuditsTerminalStatus()
    {
        var invitationId = Guid.NewGuid();
        var repository = new RecordingInvitationRepository
        {
            RevokeResult = new RevokeInvitationByIdAdministrationResult(invitationId, null, InvitationAdministrationRevocationStatus.AlreadyAccepted, InvitationAdministrationStatus.Accepted, null)
        };

        var events = new RecordingSecurityEventSink();
        var result = await CreateService(repository, events).RevokeInvitationByIdAsync(MutationBoundary.Actor, new RevokeInvitationByIdAdministrationRequest(invitationId, TenantContext.Global, Reason: "operator request"));

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
    public async Task RevokeInvitationByIdAsyncMapsMissingInvitationSafely()
    {
        var result = await CreateService().RevokeInvitationByIdAsync(MutationBoundary.Actor, new RevokeInvitationByIdAdministrationRequest(Guid.NewGuid(), TenantContext.Global));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvitationNotFound));
    }

    [Test]
    public async Task RevokeInvitationByIdAsyncRecordsTenantScopedAuditProperties()
    {
        var invitationId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var events = new RecordingSecurityEventSink();
        var repository = new RecordingInvitationRepository
        {
            RevokeResult = new RevokeInvitationByIdAdministrationResult(invitationId, tenantId, InvitationAdministrationRevocationStatus.Revoked, InvitationAdministrationStatus.Revoked, Now)
        };

        await CreateService(repository, events).RevokeInvitationByIdAsync(MutationBoundary.Actor, new RevokeInvitationByIdAdministrationRequest(invitationId, new TenantContext(tenantId)));

        var securityEvent = events.Events.Single();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(securityEvent.TenantId, Is.EqualTo(tenantId));
            Assert.That(securityEvent.SessionId, Is.EqualTo(MutationBoundary.Actor.CurrentSessionId));
            Assert.That(securityEvent.Properties?["tenant_scope"], Is.EqualTo("tenant"));
            Assert.That(securityEvent.Properties?["tenant_id"], Is.EqualTo(tenantId.ToString()));
            Assert.That(securityEvent.Properties?.ContainsKey("reason"), Is.False);
        }
    }

    [Test]
    public async Task RevokeInvitationByIdAsyncRecordsGlobalAuditPropertiesWithReason()
    {
        var invitationId = Guid.NewGuid();
        var events = new RecordingSecurityEventSink();
        var repository = new RecordingInvitationRepository
        {
            RevokeResult = new RevokeInvitationByIdAdministrationResult(invitationId, null, InvitationAdministrationRevocationStatus.Revoked, InvitationAdministrationStatus.Revoked, Now)
        };

        await CreateService(repository, events).RevokeInvitationByIdAsync(MutationBoundary.Actor, new RevokeInvitationByIdAdministrationRequest(invitationId, TenantContext.Global, Reason: "cleanup"));

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
    public async Task RevokeInvitationByIdAsyncRecordsAllTenantAuditScopeWithInvitationTenantId()
    {
        var invitationId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var events = new RecordingSecurityEventSink();
        var repository = new RecordingInvitationRepository
        {
            RevokeResult = new RevokeInvitationByIdAdministrationResult(invitationId, tenantId, InvitationAdministrationRevocationStatus.Revoked, InvitationAdministrationStatus.Revoked, Now)
        };

        await CreateService(repository, events).RevokeInvitationByIdAsync(MutationBoundary.Actor, new RevokeInvitationByIdAdministrationRequest(invitationId, IncludeAllTenants: true));

        var securityEvent = events.Events.Single();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(securityEvent.TenantId, Is.EqualTo(tenantId));
            Assert.That(securityEvent.Properties?["tenant_scope"], Is.EqualTo("all"));
            Assert.That(securityEvent.Properties?["tenant_id"], Is.EqualTo(tenantId.ToString()));
        }
    }

    [Test]
    public async Task RevokeInvitationByIdAsyncShouldCommitWhenTransactionProviderIsConfigured()
    {
        var transactionProvider = new RecordingTransactionProvider();
        var invitationId = Guid.NewGuid();
        var repository = new RecordingInvitationRepository
        {
            RevokeResult = new RevokeInvitationByIdAdministrationResult(invitationId, null, InvitationAdministrationRevocationStatus.Revoked, InvitationAdministrationStatus.Revoked, Now)
        };

        var result = await CreateService(repository, transactionProvider: transactionProvider)
            .RevokeInvitationByIdAsync(MutationBoundary.Actor, new RevokeInvitationByIdAdministrationRequest(invitationId, TenantContext.Global));

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
        new(repository, dependencies, new RecordingMutationExecutor(), MutationBoundary.Sessions, MutationBoundary.Authorizer, MutationBoundary.Sink);

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

    private static InvitationAdministrationService CreateService(AdminReadTestBoundary boundary, IInvitationMutationExecutor mutations)
    {
        var repository = new RecordingInvitationRepository();
        var composition = new DurableSecurityMutationTestComposition(null, repository);
        return new InvitationAdministrationService(repository,
            new(new StaticTimeProvider(Now), composition.Events, composition.Transactions), mutations,
            boundary.Sessions, boundary.Authorizer, boundary.Sink);
    }

    private static AccountSecurityActorContext CopyActorWithAudit(AccountSecurityActorContext actor, AuditContext audit) =>
        new(actor.ActorUserId, actor.ActorTenant, actor.CurrentSessionId, actor.FreshMfaProof, audit);

    private sealed class RecordingInvitationRepository : IInvitationRepository
    {
        public List<InvitationAdministrationSummary> SearchResults { get; } = [];
        public SearchInvitationsRequest? LastSearchRequest { get; private set; }
        public DateTimeOffset? LastSearchNow { get; private set; }
        public InvitationAdministrationSummary? SingleResult { get; init; }
        public int GetCalls { get; private set; }
        public RevokeInvitationByIdAdministrationRequest? LastRevokeRequest { get; private set; }
        public DateTimeOffset? LastRevokeNow { get; private set; }
        public RevokeInvitationByIdAdministrationResult? RevokeResult { get; init; }

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
            GetCalls++;
            return Task.FromResult(SingleResult);
        }

        public Task<RevokeInvitationByIdAdministrationResult?> RevokeInvitationByIdAsync(RevokeInvitationByIdAdministrationRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
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

    private sealed class RecordingMutationExecutor : IInvitationMutationExecutor
    {
        public List<CreateInvitationRequest> Created { get; } = [];
        public List<RevokeInvitationsByEmailAdministrationRequest> Revoked { get; } = [];
        public AuthenticationContext? LastContext { get; private set; }
        public AuditContext? LastAudit { get; private set; }
        public Guid? LastSessionId { get; private set; }
        public Result<RevokeInvitationsByEmailAdministrationResult> RevokeResult { get; set; } =
            Result.Success(new RevokeInvitationsByEmailAdministrationResult(1));
        public bool RejectCreation { get; set; }
        public bool RejectRevocation { get; set; }

        public void ValidateCreateInvitation(CreateInvitationRequest request, Uri callbackBaseUri)
        {
            if (RejectCreation)
                throw new ArgumentException("Invalid invitation creation request.");
        }

        public void ValidateRevokeInvitationsByEmail(RevokeInvitationsByEmailAdministrationRequest request)
        {
            AdministrationScopeValidation.ThrowIfInvalidScope(request.Tenant, request.IncludeAllTenants);
            if (RejectRevocation)
                throw new ArgumentException("Invalid invitation revocation request.");
        }

        public Task<Result> CreateInvitationAsync(CreateInvitationRequest request, Uri callbackBaseUri,
            AuthenticationContext context, CancellationToken cancellationToken = default)
        {
            Created.Add(request);
            LastContext = context;
            return Task.FromResult(Result.Success());
        }

        public Task<Result<RevokeInvitationsByEmailAdministrationResult>> RevokeInvitationsByEmailAsync(RevokeInvitationsByEmailAdministrationRequest request, AuditContext audit,
            Guid currentSessionId, CancellationToken cancellationToken = default)
        {
            Revoked.Add(request);
            LastAudit = audit;
            LastSessionId = currentSessionId;
            return Task.FromResult(RevokeResult);
        }
    }

    private sealed class StaticTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
