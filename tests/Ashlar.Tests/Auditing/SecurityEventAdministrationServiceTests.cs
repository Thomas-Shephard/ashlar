using Ashlar.Auditing;

namespace Ashlar.Tests.Auditing;

using Ashlar.Tests.Support;

internal sealed class SecurityEventAdministrationServiceTests
{
    private AdminReadTestBoundary _boundary = null!;
    private AccountSecurityActorContext Actor => _boundary.Actor;
    private AdminReadTestBoundary.RecordingSink Sink => _boundary.Sink;

    [SetUp]
    public void SetUp() => _boundary = new AdminReadTestBoundary(DateTimeOffset.UtcNow);

    [Test]
    public void ConstructorRejectsNullRepository()
    {
        Assert.Throws<ArgumentNullException>(() => new SecurityEventAdministrationService(null!, null!, null!, null!));
    }

    [Test]
    public void SearchSecurityEventsAsyncRejectsNullRequest()
    {
        var service = CreateService();

        Assert.ThrowsAsync<ArgumentNullException>(async () => await service.SearchSecurityEventsAsync(Actor, null!));
    }

    [TestCase(0)]
    [TestCase(-1)]
    public async Task SearchSecurityEventsAsyncRejectsInvalidLimit(int limit)
    {
        var result = await CreateService().SearchSecurityEventsAsync(Actor, new SearchSecurityEventsRequest { IncludeAllTenants = true, Limit = limit });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public async Task SearchSecurityEventsAsyncRejectsNegativeOffset()
    {
        var result = await CreateService().SearchSecurityEventsAsync(Actor, new SearchSecurityEventsRequest { IncludeAllTenants = true, Offset = -1 });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public async Task SearchSecurityEventsAsyncRejectsMissingAndConflictingTenantScope()
    {
        var service = CreateService();

        var missing = await service.SearchSecurityEventsAsync(Actor, new SearchSecurityEventsRequest { Limit = 10 });
        var conflicting = await service.SearchSecurityEventsAsync(Actor, new SearchSecurityEventsRequest { Tenant = TenantContext.Global, IncludeAllTenants = true, Limit = 10 });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missing.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(conflicting.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public async Task SearchSecurityEventsAsyncCapsLimitAndUsesExtraRowForHasMore()
    {
        var repository = new RecordingSecurityEventAdministrationRepository();
        for (var i = 0; i < 101; i++)
        {
            repository.SearchResults.Add(CreateSummary());
        }

        var result = await CreateService(repository).SearchSecurityEventsAsync(Actor, new SearchSecurityEventsRequest { IncludeAllTenants = true, Limit = 500, Offset = 7 });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.Items, Has.Count.EqualTo(100));
            Assert.That(result.Value?.Limit, Is.EqualTo(100));
            Assert.That(result.Value?.Offset, Is.EqualTo(7));
            Assert.That(result.Value?.HasMore, Is.True);
            Assert.That(repository.LastSearchRequest?.Limit, Is.EqualTo(101));
            Assert.That(repository.LastSearchRequest?.Offset, Is.EqualTo(7));
        }
    }

    [Test]
    public async Task SearchSecurityEventsAsyncDelegatesFiltersToRepository()
    {
        var tenant = new TenantContext(Guid.NewGuid());
        var provider = AuthenticationProviderKey.Local;
        var eventTypes = new HashSet<string>(StringComparer.Ordinal) { "SignInSucceeded" };
        var repository = new RecordingSecurityEventAdministrationRepository();
        var expected = CreateSummary() with { TenantId = tenant.TenantId };
        repository.SearchResults.Add(expected);

        var request = new SearchSecurityEventsRequest
        {
            Tenant = tenant,
            UserId = expected.UserId,
            ActorUserId = Guid.NewGuid(),
            SessionId = Guid.NewGuid(),
            EventTypes = eventTypes,
            Outcome = SecurityEventOutcomes.Success,
            FailureReason = "ignored",
            Provider = provider,
            OccurredFrom = DateTimeOffset.UtcNow.AddDays(-1),
            OccurredTo = DateTimeOffset.UtcNow,
            Limit = 25,
            Offset = 5
        };

        var result = await CreateService(repository).SearchSecurityEventsAsync(Actor, request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.Items.Single(), Is.EqualTo(expected));
            Assert.That(repository.LastSearchRequest?.Tenant, Is.SameAs(tenant));
            Assert.That(repository.LastSearchRequest?.UserId, Is.EqualTo(request.UserId));
            Assert.That(repository.LastSearchRequest?.ActorUserId, Is.EqualTo(request.ActorUserId));
            Assert.That(repository.LastSearchRequest?.SessionId, Is.EqualTo(request.SessionId));
            Assert.That(repository.LastSearchRequest?.EventTypes, Is.SameAs(eventTypes));
            Assert.That(repository.LastSearchRequest?.Outcome, Is.EqualTo(request.Outcome));
            Assert.That(repository.LastSearchRequest?.FailureReason, Is.EqualTo(request.FailureReason));
            Assert.That(repository.LastSearchRequest?.Provider, Is.EqualTo(provider));
            Assert.That(repository.LastSearchRequest?.OccurredFrom, Is.EqualTo(request.OccurredFrom));
            Assert.That(repository.LastSearchRequest?.OccurredTo, Is.EqualTo(request.OccurredTo));
            Assert.That(repository.LastSearchRequest?.Limit, Is.EqualTo(26));
        }
    }

    [Test]
    public async Task GetSecurityEventAsyncRejectsEmptyEventId()
    {
        var result = await CreateService().GetSecurityEventAsync(Actor, new SecurityEventAdministrationLookupRequest(Guid.Empty, TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public async Task GetSecurityEventAsyncMapsMissingEventSafely()
    {
        var service = CreateService();
        var result = await service.GetSecurityEventAsync(Actor, new SecurityEventAdministrationLookupRequest(Guid.NewGuid(), TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.SecurityEventNotFound));
            Assert.That(Sink.Events.Single().Outcome, Is.EqualTo(SecurityEventOutcomes.Failure));
        }
    }

    [Test]
    public async Task GetSecurityEventAsyncReturnsRepositoryResult()
    {
        var expected = CreateSummary() with { UserId = null };
        var repository = new RecordingSecurityEventAdministrationRepository { GetResult = expected };

        var request = new SecurityEventAdministrationLookupRequest(expected.EventId, TenantContext.Global);
        var result = await CreateService(repository).GetSecurityEventAsync(Actor, request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value, Is.EqualTo(expected));
            Assert.That(repository.LastGetRequest, Is.EqualTo(request));
        }
    }

    [Test]
    public async Task GetSecurityEventAsyncDurablyAuditsSuccessfulReadExactlyOnce()
    {
        var expected = CreateSummary() with { UserId = null };
        var service = CreateService(new RecordingSecurityEventAdministrationRepository { GetResult = expected });

        var result = await service.GetSecurityEventAsync(Actor, new SecurityEventAdministrationLookupRequest(expected.EventId, TenantContext.Global));

        var audit = Sink.Events.Single();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(audit.Outcome, Is.EqualTo(SecurityEventOutcomes.Success));
            Assert.That(audit.Properties?["operation"], Is.EqualTo(AccountSecurityOperation.ReadSecurityEvent.ToString()));
        }
    }

    [Test]
    public void GetSecurityEventAsyncFailsClosedWhenSuccessAuditFails()
    {
        var boundary = new AdminReadTestBoundary(DateTimeOffset.UtcNow);
        var expected = CreateSummary() with { UserId = null };
        var service = new SecurityEventAdministrationService(
            new RecordingSecurityEventAdministrationRepository { GetResult = expected }, boundary.Sessions,
            boundary.Authorizer, new ThrowingPersistentSink(), boundary.TimeProvider);

        Assert.ThrowsAsync<InvalidOperationException>(() => service.GetSecurityEventAsync(
            boundary.Actor, new SecurityEventAdministrationLookupRequest(expected.EventId, TenantContext.Global)));
    }

    [Test]
    public async Task GetSecurityEventAsyncMapsOutOfScopeEventSafely()
    {
        var tenantId = Guid.NewGuid();
        var expected = CreateSummary() with { TenantId = tenantId };
        var repository = new RecordingSecurityEventAdministrationRepository { GetResult = expected };

        var service = CreateService(repository);
        var result = await service.GetSecurityEventAsync(Actor, new SecurityEventAdministrationLookupRequest(expected.EventId, TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.SecurityEventNotFound));
            Assert.That(Sink.Events.Single().Outcome, Is.EqualTo(SecurityEventOutcomes.Failure));
        }
    }

    [Test]
    public async Task GetSecurityEventAsyncAllowsExplicitAllTenantDetail()
    {
        var expected = CreateSummary() with { TenantId = Guid.NewGuid() };
        var repository = new RecordingSecurityEventAdministrationRepository { GetResult = expected };

        var result = await CreateService(repository).GetSecurityEventAsync(Actor, new SecurityEventAdministrationLookupRequest(expected.EventId, IncludeAllTenants: true));

        Assert.That(result.Value, Is.EqualTo(expected));
    }

    [Test]
    public async Task GetSecurityEventAsyncRejectsMissingAndConflictingTenantScope()
    {
        var service = CreateService();
        var eventId = Guid.NewGuid();

        var missing = await service.GetSecurityEventAsync(Actor, new SecurityEventAdministrationLookupRequest(eventId));
        var conflicting = await service.GetSecurityEventAsync(Actor, new SecurityEventAdministrationLookupRequest(eventId, TenantContext.Global, IncludeAllTenants: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missing.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(conflicting.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public void SearchSecurityEventsAsyncAuditsProviderFailure()
    {
        var repository = new RecordingSecurityEventAdministrationRepository { SearchException = new InvalidOperationException() };
        Assert.ThrowsAsync<InvalidOperationException>(() => CreateService(repository).SearchSecurityEventsAsync(Actor,
            new SearchSecurityEventsRequest { Tenant = TenantContext.Global }));
    }

    [Test]
    public void SearchSecurityEventsAsyncRejectsOutOfScopePaginationSentinel()
    {
        var tenant = new TenantContext(Guid.NewGuid());
        var userId = Guid.NewGuid();
        var repository = new RecordingSecurityEventAdministrationRepository();
        repository.SearchResults.Add(CreateSummary() with { TenantId = tenant.TenantId, UserId = userId });
        repository.SearchResults.Add(CreateSummary() with { TenantId = tenant.TenantId, UserId = Guid.NewGuid() });

        Assert.ThrowsAsync<InvalidOperationException>(() => CreateService(repository).SearchSecurityEventsAsync(Actor,
            new SearchSecurityEventsRequest { Tenant = tenant, UserId = userId, Limit = 1 }));
    }

    private SecurityEventAdministrationService CreateService(RecordingSecurityEventAdministrationRepository? repository = null)
    {
        return new SecurityEventAdministrationService(repository ?? new RecordingSecurityEventAdministrationRepository(),
            _boundary.Sessions, _boundary.Authorizer, _boundary.Sink, _boundary.TimeProvider);
    }

    private static SecurityEventSummary CreateSummary()
    {
        return new SecurityEventSummary(
            Guid.NewGuid(),
            "TestEvent",
            DateTimeOffset.UtcNow,
            Guid.NewGuid(),
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            SecurityEventOutcomes.Success,
            null,
            null);
    }

    private sealed class RecordingSecurityEventAdministrationRepository : ISecurityEventAdministrationRepository
    {
        public List<SecurityEventSummary> SearchResults { get; } = [];
        public SearchSecurityEventsRequest? LastSearchRequest { get; private set; }
        public SecurityEventAdministrationLookupRequest? LastGetRequest { get; private set; }
        public SecurityEventSummary? GetResult { get; init; }

        public Exception? SearchException { get; init; }

        public Task<IReadOnlyList<SecurityEventSummary>> SearchSecurityEventsAsync(SearchSecurityEventsRequest request, CancellationToken cancellationToken = default)
        {
            if (SearchException is not null) throw SearchException;
            LastSearchRequest = request;
            return Task.FromResult<IReadOnlyList<SecurityEventSummary>>(SearchResults.AsReadOnly());
        }

        public Task<SecurityEventSummary?> GetSecurityEventAsync(SecurityEventAdministrationLookupRequest request, CancellationToken cancellationToken = default)
        {
            LastGetRequest = request;
            return Task.FromResult(GetResult);
        }
    }

    private sealed class ThrowingPersistentSink : IPersistentSecurityEventSink
    {
        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("Audit failed.");
    }
}
