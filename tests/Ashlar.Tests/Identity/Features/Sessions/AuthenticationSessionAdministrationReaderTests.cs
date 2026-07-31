namespace Ashlar.Tests.Identity.Features.Sessions;

using Ashlar.Tests.Support;

internal sealed class AuthenticationSessionAdministrationReaderTests
{
    private static readonly DateTimeOffset Now = new(2026, 6, 2, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public void ConstructorRejectsNullRepository()
    {
        Assert.Throws<ArgumentNullException>(() => new AuthenticationSessionAdministrationReader(null!, null!, null!, null!));
    }

    [Test]
    public async Task ConstructorUsesSystemTimeProviderByDefault()
    {
        var repository = new RecordingAuthenticationSessionAdministrationRepository();
        var before = TimeProvider.System.GetUtcNow();
        var result = await CreateService(repository, TimeProvider.System).SearchAuthenticationSessionsAsync(new SearchAuthenticationSessionsRequest { IncludeAllTenants = true });
        var after = TimeProvider.System.GetUtcNow();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(repository.LastSearchNow, Is.GreaterThanOrEqualTo(before));
            Assert.That(repository.LastSearchNow, Is.LessThanOrEqualTo(after));
        }
    }

    [Test]
    public void SearchAuthenticationSessionsAsyncRejectsNullRequest()
    {
        var service = CreateService();

        Assert.ThrowsAsync<ArgumentNullException>(async () => await service.SearchAuthenticationSessionsAsync(null!));
    }

    [TestCase(0)]
    [TestCase(-1)]
    public async Task SearchAuthenticationSessionsAsyncRejectsInvalidLimit(int limit)
    {
        var result = await CreateService().SearchAuthenticationSessionsAsync(new SearchAuthenticationSessionsRequest { IncludeAllTenants = true, Limit = limit });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public async Task SearchAuthenticationSessionsAsyncRejectsNegativeOffset()
    {
        var result = await CreateService().SearchAuthenticationSessionsAsync(new SearchAuthenticationSessionsRequest { IncludeAllTenants = true, Offset = -1 });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public async Task SearchAuthenticationSessionsAsyncRejectsMissingAndConflictingTenantScope()
    {
        var service = CreateService();

        var missing = await service.SearchAuthenticationSessionsAsync(new SearchAuthenticationSessionsRequest { Limit = 10 });
        var conflicting = await service.SearchAuthenticationSessionsAsync(new SearchAuthenticationSessionsRequest { Tenant = TenantContext.Global, IncludeAllTenants = true, Limit = 10 });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missing.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(conflicting.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public async Task SearchAuthenticationSessionsAsyncCapsLimitAndUsesExtraRowForHasMore()
    {
        var repository = new RecordingAuthenticationSessionAdministrationRepository();
        for (var i = 0; i < 101; i++)
        {
            repository.SearchResults.Add(CreateSummary());
        }

        var result = await CreateService(repository).SearchAuthenticationSessionsAsync(new SearchAuthenticationSessionsRequest { IncludeAllTenants = true, Limit = 500, Offset = 7 });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.Items, Has.Count.EqualTo(100));
            Assert.That(result.Value?.Limit, Is.EqualTo(100));
            Assert.That(result.Value?.Offset, Is.EqualTo(7));
            Assert.That(result.Value?.HasMore, Is.True);
            Assert.That(repository.LastSearchRequest?.Limit, Is.EqualTo(101));
            Assert.That(repository.LastSearchRequest?.Offset, Is.EqualTo(7));
            Assert.That(repository.LastSearchNow, Is.EqualTo(Now));
        }
    }

    [Test]
    public async Task SearchAuthenticationSessionsAsyncDelegatesFiltersToRepository()
    {
        var tenant = new TenantContext(Guid.NewGuid());
        var provider = AuthenticationProviderKey.Local;
        var repository = new RecordingAuthenticationSessionAdministrationRepository();
        var expected = CreateSummary() with { TenantId = tenant.TenantId };
        repository.SearchResults.Add(expected);

        var request = new SearchAuthenticationSessionsRequest
        {
            Tenant = tenant,
            UserId = expected.UserId,
            PrimaryProvider = provider,
            Active = true,
            Revoked = false,
            CreatedFrom = Now.AddDays(-1),
            CreatedTo = Now,
            ExpiresFrom = Now.AddDays(1),
            ExpiresTo = Now.AddDays(2),
            LastSeenFrom = Now.AddMinutes(-5),
            LastSeenTo = Now,
            Limit = 25,
            Offset = 5
        };

        var result = await CreateService(repository).SearchAuthenticationSessionsAsync(request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.Items.Single(), Is.EqualTo(expected));
            Assert.That(repository.LastSearchRequest?.Tenant, Is.SameAs(tenant));
            Assert.That(repository.LastSearchRequest?.UserId, Is.EqualTo(request.UserId));
            Assert.That(repository.LastSearchRequest?.PrimaryProvider, Is.EqualTo(provider));
            Assert.That(repository.LastSearchRequest?.Active, Is.True);
            Assert.That(repository.LastSearchRequest?.Revoked, Is.False);
            Assert.That(repository.LastSearchRequest?.CreatedFrom, Is.EqualTo(request.CreatedFrom));
            Assert.That(repository.LastSearchRequest?.CreatedTo, Is.EqualTo(request.CreatedTo));
            Assert.That(repository.LastSearchRequest?.ExpiresFrom, Is.EqualTo(request.ExpiresFrom));
            Assert.That(repository.LastSearchRequest?.ExpiresTo, Is.EqualTo(request.ExpiresTo));
            Assert.That(repository.LastSearchRequest?.LastSeenFrom, Is.EqualTo(request.LastSeenFrom));
            Assert.That(repository.LastSearchRequest?.LastSeenTo, Is.EqualTo(request.LastSeenTo));
            Assert.That(repository.LastSearchRequest?.Limit, Is.EqualTo(26));
        }
    }

    [Test]
    public async Task GetAuthenticationSessionAsyncRejectsEmptySessionId()
    {
        var result = await CreateService().GetAuthenticationSessionAsync(new AuthenticationSessionAdministrationLookupRequest(Guid.Empty, TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public async Task GetAuthenticationSessionAsyncMapsMissingSessionSafely()
    {
        var result = await CreateService().GetAuthenticationSessionAsync(new AuthenticationSessionAdministrationLookupRequest(Guid.NewGuid(), TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.SessionNotFound));
        }
    }

    [Test]
    public async Task GetAuthenticationSessionAsyncReturnsRepositoryResult()
    {
        var expected = CreateSingleResult();
        var repository = new RecordingAuthenticationSessionAdministrationRepository { GetResult = expected };

        var request = new AuthenticationSessionAdministrationLookupRequest(expected.Id, TenantContext.Global);
        var result = await CreateService(repository).GetAuthenticationSessionAsync(request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value, Is.EqualTo(expected));
            Assert.That(repository.LastGetRequest, Is.EqualTo(request));
            Assert.That(repository.LastGetNow, Is.EqualTo(Now));
        }
    }

    [Test]
    public async Task GetAuthenticationSessionAsyncMapsOutOfScopeSessionSafely()
    {
        var tenantId = Guid.NewGuid();
        var expected = CreateSingleResult() with { TenantId = tenantId };
        var repository = new RecordingAuthenticationSessionAdministrationRepository { GetResult = expected };

        var result = await CreateService(repository).GetAuthenticationSessionAsync(new AuthenticationSessionAdministrationLookupRequest(expected.Id, TenantContext.Global));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.SessionNotFound));
    }

    [Test]
    public async Task GetAuthenticationSessionAsyncAllowsExplicitAllTenantLookup()
    {
        var expected = CreateSingleResult() with { TenantId = Guid.NewGuid() };
        var repository = new RecordingAuthenticationSessionAdministrationRepository { GetResult = expected };

        var result = await CreateService(repository).GetAuthenticationSessionAsync(new AuthenticationSessionAdministrationLookupRequest(expected.Id, IncludeAllTenants: true));

        Assert.That(result.Value, Is.EqualTo(expected));
    }

    [Test]
    public async Task GetAuthenticationSessionAsyncRejectsMissingAndConflictingTenantScope()
    {
        var service = CreateService();
        var sessionId = Guid.NewGuid();

        var missing = await service.GetAuthenticationSessionAsync(new AuthenticationSessionAdministrationLookupRequest(sessionId));
        var conflicting = await service.GetAuthenticationSessionAsync(new AuthenticationSessionAdministrationLookupRequest(sessionId, TenantContext.Global, IncludeAllTenants: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missing.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(conflicting.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public void AuthenticationSessionAdministrationModelsDoNotExposeTokenHash()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(typeof(AuthenticationSessionAdministrationSummary).GetProperties().Select(static property => property.Name), Does.Not.Contain("TokenHash"));
            Assert.That(typeof(AuthenticationSessionAdministrationSummary).GetProperties().Select(static property => property.Name), Does.Not.Contain("TokenHash"));
        }
    }

    [Test]
    public void SearchAuthenticationSessionsAsyncAuditsProviderFailure()
    {
        var repository = new RecordingAuthenticationSessionAdministrationRepository { SearchException = new InvalidOperationException() };
        Assert.ThrowsAsync<InvalidOperationException>(() => CreateService(repository).SearchAuthenticationSessionsAsync(
            new SearchAuthenticationSessionsRequest { Tenant = TenantContext.Global }));
    }

    [Test]
    public void SearchAuthenticationSessionsAsyncRejectsOutOfScopePaginationSentinel()
    {
        var tenant = new TenantContext(Guid.NewGuid());
        var userId = Guid.NewGuid();
        var repository = new RecordingAuthenticationSessionAdministrationRepository();
        repository.SearchResults.Add(CreateSummary() with { TenantId = tenant.TenantId, UserId = userId });
        repository.SearchResults.Add(CreateSummary() with { TenantId = Guid.NewGuid(), UserId = userId });

        Assert.ThrowsAsync<InvalidOperationException>(() => CreateService(repository).SearchAuthenticationSessionsAsync(
            new SearchAuthenticationSessionsRequest { Tenant = tenant, UserId = userId, Limit = 1 }));
    }

    private static AuthorizedSessionAdministrationReader CreateService(RecordingAuthenticationSessionAdministrationRepository? repository = null, TimeProvider? timeProvider = null)
    {
        var boundary = new AdminReadTestBoundary(timeProvider?.GetUtcNow() ?? Now);
        return new AuthorizedSessionAdministrationReader(new AuthenticationSessionAdministrationReader(
            repository ?? new RecordingAuthenticationSessionAdministrationRepository(), boundary.Sessions,
            boundary.Authorizer, boundary.Sink, timeProvider ?? new StaticTimeProvider(Now)), boundary.Actor);
    }

    private sealed class AuthorizedSessionAdministrationReader(AuthenticationSessionAdministrationReader reader, AccountSecurityActorContext actor)
    {
        public Task<Result<AuthenticationSessionSearchResult>> SearchAuthenticationSessionsAsync(SearchAuthenticationSessionsRequest request) =>
            reader.SearchAuthenticationSessionsAsync(actor, request);
        public Task<Result<AuthenticationSessionAdministrationSummary>> GetAuthenticationSessionAsync(AuthenticationSessionAdministrationLookupRequest request) =>
            reader.GetAuthenticationSessionAsync(actor, request);
    }

    private static AuthenticationSessionAdministrationSummary CreateSummary()
    {
        return new AuthenticationSessionAdministrationSummary(
            Guid.NewGuid(),
            Guid.NewGuid(),
            null,
            Now,
            Now,
            AuthenticationProviderKey.Local,
            null,
            null,
            null,
            Now.AddDays(1),
            null,
            null,
            null,
            null,
            null,
            true);
    }

    private static AuthenticationSessionAdministrationSummary CreateSingleResult()
    {
        var summary = CreateSummary();
        return new AuthenticationSessionAdministrationSummary(
            summary.Id,
            summary.UserId,
            summary.TenantId,
            summary.CreatedAt,
            summary.AuthenticatedAt,
            summary.PrimaryProvider,
            summary.AdditionalVerificationAt,
            summary.AdditionalVerificationProvider,
            summary.AdditionalVerificationFactor,
            summary.ExpiresAt,
            summary.LastSeenAt,
            summary.RevokedAt,
            summary.RevocationReason,
            summary.IpAddress,
            summary.UserAgent,
            summary.IsActive);
    }

    private sealed class RecordingAuthenticationSessionAdministrationRepository : IAuthenticationSessionAdministrationRepository
    {
        public List<AuthenticationSessionAdministrationSummary> SearchResults { get; } = [];
        public SearchAuthenticationSessionsRequest? LastSearchRequest { get; private set; }
        public DateTimeOffset? LastSearchNow { get; private set; }
        public AuthenticationSessionAdministrationLookupRequest? LastGetRequest { get; private set; }
        public DateTimeOffset? LastGetNow { get; private set; }
        public AuthenticationSessionAdministrationSummary? GetResult { get; init; }
        public Exception? SearchException { get; init; }

        public Task<IReadOnlyList<AuthenticationSessionAdministrationSummary>> SearchAuthenticationSessionsAsync(SearchAuthenticationSessionsRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            if (SearchException is not null) throw SearchException;
            LastSearchRequest = request;
            LastSearchNow = now;
            return Task.FromResult<IReadOnlyList<AuthenticationSessionAdministrationSummary>>(SearchResults.AsReadOnly());
        }

        public Task<AuthenticationSessionAdministrationSummary?> GetAuthenticationSessionAsync(AuthenticationSessionAdministrationLookupRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            LastGetRequest = request;
            LastGetNow = now;
            return Task.FromResult(GetResult);
        }
    }

    private sealed class StaticTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            return now;
        }
    }
}
