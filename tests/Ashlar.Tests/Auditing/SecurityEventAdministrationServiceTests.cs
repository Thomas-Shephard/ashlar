using Ashlar.Auditing;

namespace Ashlar.Tests.Auditing;

internal sealed class SecurityEventAdministrationServiceTests
{
    [Test]
    public void ConstructorRejectsNullRepository()
    {
        Assert.Throws<ArgumentNullException>(() => new SecurityEventAdministrationService(null!));
    }

    [Test]
    public void SearchSecurityEventsAsyncRejectsNullRequest()
    {
        var service = CreateService();

        Assert.ThrowsAsync<ArgumentNullException>(async () => await service.SearchSecurityEventsAsync(null!));
    }

    [TestCase(0)]
    [TestCase(-1)]
    public async Task SearchSecurityEventsAsyncRejectsInvalidLimit(int limit)
    {
        var result = await CreateService().SearchSecurityEventsAsync(new SearchSecurityEventsRequest { IncludeAllTenants = true, Limit = limit });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public async Task SearchSecurityEventsAsyncRejectsNegativeOffset()
    {
        var result = await CreateService().SearchSecurityEventsAsync(new SearchSecurityEventsRequest { IncludeAllTenants = true, Offset = -1 });

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

        var missing = await service.SearchSecurityEventsAsync(new SearchSecurityEventsRequest { Limit = 10 });
        var conflicting = await service.SearchSecurityEventsAsync(new SearchSecurityEventsRequest { Tenant = TenantContext.Global, IncludeAllTenants = true, Limit = 10 });

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

        var result = await CreateService(repository).SearchSecurityEventsAsync(new SearchSecurityEventsRequest { IncludeAllTenants = true, Limit = 500, Offset = 7 });

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
        var expected = CreateSummary();
        repository.SearchResults.Add(expected);

        var request = new SearchSecurityEventsRequest
        {
            Tenant = tenant,
            UserId = Guid.NewGuid(),
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

        var result = await CreateService(repository).SearchSecurityEventsAsync(request);

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
        var result = await CreateService().GetSecurityEventAsync(new SecurityEventAdministrationDetailRequest(Guid.Empty, TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public async Task GetSecurityEventAsyncMapsMissingEventSafely()
    {
        var result = await CreateService().GetSecurityEventAsync(new SecurityEventAdministrationDetailRequest(Guid.NewGuid(), TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.SecurityEventNotFound));
        }
    }

    [Test]
    public async Task GetSecurityEventAsyncReturnsRepositoryResult()
    {
        var expected = CreateSummary();
        var repository = new RecordingSecurityEventAdministrationRepository { GetResult = expected };

        var request = new SecurityEventAdministrationDetailRequest(expected.EventId, TenantContext.Global);
        var result = await CreateService(repository).GetSecurityEventAsync(request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value, Is.EqualTo(expected));
            Assert.That(repository.LastGetRequest, Is.SameAs(request));
        }
    }

    [Test]
    public async Task GetSecurityEventAsyncMapsOutOfScopeEventSafely()
    {
        var tenantId = Guid.NewGuid();
        var expected = CreateSummary() with { TenantId = tenantId };
        var repository = new RecordingSecurityEventAdministrationRepository { GetResult = expected };

        var result = await CreateService(repository).GetSecurityEventAsync(new SecurityEventAdministrationDetailRequest(expected.EventId, TenantContext.Global));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.SecurityEventNotFound));
    }

    [Test]
    public async Task GetSecurityEventAsyncAllowsExplicitAllTenantDetail()
    {
        var expected = CreateSummary() with { TenantId = Guid.NewGuid() };
        var repository = new RecordingSecurityEventAdministrationRepository { GetResult = expected };

        var result = await CreateService(repository).GetSecurityEventAsync(new SecurityEventAdministrationDetailRequest(expected.EventId, IncludeAllTenants: true));

        Assert.That(result.Value, Is.EqualTo(expected));
    }

    [Test]
    public async Task GetSecurityEventAsyncRejectsMissingAndConflictingTenantScope()
    {
        var service = CreateService();
        var eventId = Guid.NewGuid();

        var missing = await service.GetSecurityEventAsync(new SecurityEventAdministrationDetailRequest(eventId));
        var conflicting = await service.GetSecurityEventAsync(new SecurityEventAdministrationDetailRequest(eventId, TenantContext.Global, IncludeAllTenants: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missing.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(conflicting.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    private static SecurityEventAdministrationService CreateService(RecordingSecurityEventAdministrationRepository? repository = null)
    {
        return new SecurityEventAdministrationService(repository ?? new RecordingSecurityEventAdministrationRepository());
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
        public SecurityEventAdministrationDetailRequest? LastGetRequest { get; private set; }
        public SecurityEventSummary? GetResult { get; init; }

        public Task<IReadOnlyList<SecurityEventSummary>> SearchSecurityEventsAsync(SearchSecurityEventsRequest request, CancellationToken cancellationToken = default)
        {
            LastSearchRequest = request;
            return Task.FromResult<IReadOnlyList<SecurityEventSummary>>(SearchResults.AsReadOnly());
        }

        public Task<SecurityEventSummary?> GetSecurityEventAsync(SecurityEventAdministrationDetailRequest request, CancellationToken cancellationToken = default)
        {
            LastGetRequest = request;
            return Task.FromResult(GetResult);
        }
    }
}
