namespace Ashlar.Tests.Identity.Features.Sessions;

internal sealed class AuthenticationSessionAdministrationServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 6, 2, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public void ConstructorRejectsNullRepository()
    {
        Assert.Throws<ArgumentNullException>(() => new AuthenticationSessionAdministrationService(null!));
    }

    [Test]
    public async Task ConstructorUsesSystemTimeProviderByDefault()
    {
        var repository = new RecordingAuthenticationSessionAdministrationRepository();
        var before = TimeProvider.System.GetUtcNow();
        var result = await new AuthenticationSessionAdministrationService(repository).SearchAuthenticationSessionsAsync(new SearchAuthenticationSessionsRequest());
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
        var result = await CreateService().SearchAuthenticationSessionsAsync(new SearchAuthenticationSessionsRequest { Limit = limit });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public async Task SearchAuthenticationSessionsAsyncRejectsNegativeOffset()
    {
        var result = await CreateService().SearchAuthenticationSessionsAsync(new SearchAuthenticationSessionsRequest { Offset = -1 });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
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

        var result = await CreateService(repository).SearchAuthenticationSessionsAsync(new SearchAuthenticationSessionsRequest { Limit = 500, Offset = 7 });

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
        var expected = CreateSummary();
        repository.SearchResults.Add(expected);

        var request = new SearchAuthenticationSessionsRequest
        {
            Tenant = tenant,
            UserId = Guid.NewGuid(),
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
        var result = await CreateService().GetAuthenticationSessionAsync(Guid.Empty);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public async Task GetAuthenticationSessionAsyncMapsMissingSessionSafely()
    {
        var result = await CreateService().GetAuthenticationSessionAsync(Guid.NewGuid());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.SessionNotFound));
        }
    }

    [Test]
    public async Task GetAuthenticationSessionAsyncReturnsRepositoryResult()
    {
        var expected = CreateDetail();
        var repository = new RecordingAuthenticationSessionAdministrationRepository { GetResult = expected };

        var result = await CreateService(repository).GetAuthenticationSessionAsync(expected.Id);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value, Is.EqualTo(expected));
            Assert.That(repository.LastGetSessionId, Is.EqualTo(expected.Id));
            Assert.That(repository.LastGetNow, Is.EqualTo(Now));
        }
    }

    [Test]
    public void AuthenticationSessionAdministrationModelsDoNotExposeTokenHash()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(typeof(AuthenticationSessionAdministrationSummary).GetProperties().Select(static property => property.Name), Does.Not.Contain("TokenHash"));
            Assert.That(typeof(AuthenticationSessionAdministrationDetail).GetProperties().Select(static property => property.Name), Does.Not.Contain("TokenHash"));
        }
    }

    private static AuthenticationSessionAdministrationService CreateService(RecordingAuthenticationSessionAdministrationRepository? repository = null)
    {
        return new AuthenticationSessionAdministrationService(repository ?? new RecordingAuthenticationSessionAdministrationRepository(), new StaticTimeProvider(Now));
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

    private static AuthenticationSessionAdministrationDetail CreateDetail()
    {
        var summary = CreateSummary();
        return new AuthenticationSessionAdministrationDetail(
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
        public Guid? LastGetSessionId { get; private set; }
        public DateTimeOffset? LastGetNow { get; private set; }
        public AuthenticationSessionAdministrationDetail? GetResult { get; init; }

        public Task<IReadOnlyList<AuthenticationSessionAdministrationSummary>> SearchAuthenticationSessionsAsync(SearchAuthenticationSessionsRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            LastSearchRequest = request;
            LastSearchNow = now;
            return Task.FromResult<IReadOnlyList<AuthenticationSessionAdministrationSummary>>(SearchResults.AsReadOnly());
        }

        public Task<AuthenticationSessionAdministrationDetail?> GetAuthenticationSessionAsync(Guid sessionId, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            LastGetSessionId = sessionId;
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
