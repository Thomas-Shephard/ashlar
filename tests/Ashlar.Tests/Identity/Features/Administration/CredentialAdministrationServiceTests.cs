namespace Ashlar.Tests.Identity.Features.Administration;

internal sealed class CredentialAdministrationServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 6, 2, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public void ConstructorRejectsNullRepository()
    {
        Assert.Throws<ArgumentNullException>(() => new CredentialAdministrationService(null!));
    }

    [Test]
    public async Task ConstructorUsesSystemTimeProviderByDefault()
    {
        var repository = new RecordingCredentialAdministrationRepository();
        var before = TimeProvider.System.GetUtcNow();
        var result = await new CredentialAdministrationService(repository).SearchCredentialsAsync(new SearchCredentialsRequest { IncludeAllTenants = true });
        var after = TimeProvider.System.GetUtcNow();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(repository.LastSearchNow, Is.GreaterThanOrEqualTo(before));
            Assert.That(repository.LastSearchNow, Is.LessThanOrEqualTo(after));
        }
    }

    [Test]
    public void SearchCredentialsAsyncRejectsNullRequest()
    {
        var service = CreateService();

        Assert.ThrowsAsync<ArgumentNullException>(async () => await service.SearchCredentialsAsync(null!));
    }

    [TestCase(0)]
    [TestCase(-1)]
    public async Task SearchCredentialsAsyncRejectsInvalidLimit(int limit)
    {
        var result = await CreateService().SearchCredentialsAsync(new SearchCredentialsRequest { IncludeAllTenants = true, Limit = limit });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public async Task SearchCredentialsAsyncRejectsNegativeOffset()
    {
        var result = await CreateService().SearchCredentialsAsync(new SearchCredentialsRequest { IncludeAllTenants = true, Offset = -1 });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public async Task SearchCredentialsAsyncRejectsMissingAndConflictingTenantScope()
    {
        var service = CreateService();

        var missing = await service.SearchCredentialsAsync(new SearchCredentialsRequest { Limit = 10 });
        var conflicting = await service.SearchCredentialsAsync(new SearchCredentialsRequest { Tenant = TenantContext.Global, IncludeAllTenants = true, Limit = 10 });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missing.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(conflicting.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public async Task SearchCredentialsAsyncCapsLimitAndUsesExtraRowForHasMore()
    {
        var repository = new RecordingCredentialAdministrationRepository();
        for (var i = 0; i < 101; i++)
        {
            repository.SearchResults.Add(CreateSummary());
        }

        var result = await CreateService(repository).SearchCredentialsAsync(new SearchCredentialsRequest { IncludeAllTenants = true, Limit = 500, Offset = 7 });

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
    public async Task SearchCredentialsAsyncReturnsHasMoreFalseWithoutExtraRow()
    {
        var repository = new RecordingCredentialAdministrationRepository();
        repository.SearchResults.Add(CreateSummary());

        var result = await CreateService(repository).SearchCredentialsAsync(new SearchCredentialsRequest { IncludeAllTenants = true, Limit = 50 });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.Items, Has.Count.EqualTo(1));
            Assert.That(result.Value?.HasMore, Is.False);
        }
    }

    [Test]
    public async Task SearchCredentialsAsyncDelegatesFiltersToRepository()
    {
        var tenant = new TenantContext(Guid.NewGuid());
        var provider = AuthenticationProviderKey.Passkey;
        var repository = new RecordingCredentialAdministrationRepository();
        var expected = CreateSummary();
        repository.SearchResults.Add(expected);

        var request = new SearchCredentialsRequest
        {
            Tenant = tenant,
            UserId = Guid.NewGuid(),
            Provider = provider,
            Purpose = "mfa",
            Status = CredentialStatus.Active,
            Available = true,
            Revoked = false,
            CreatedFrom = Now.AddDays(-10),
            CreatedTo = Now.AddDays(-9),
            UpdatedFrom = Now.AddDays(-8),
            UpdatedTo = Now.AddDays(-7),
            LastUsedFrom = Now.AddDays(-6),
            LastUsedTo = Now.AddDays(-5),
            ExpiresFrom = Now.AddDays(1),
            ExpiresTo = Now.AddDays(2),
            Limit = 25,
            Offset = 5
        };

        var result = await CreateService(repository).SearchCredentialsAsync(request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.Items.Single(), Is.EqualTo(expected));
            Assert.That(repository.LastSearchRequest?.Tenant, Is.SameAs(tenant));
            Assert.That(repository.LastSearchRequest?.UserId, Is.EqualTo(request.UserId));
            Assert.That(repository.LastSearchRequest?.Provider, Is.EqualTo(provider));
            Assert.That(repository.LastSearchRequest?.Purpose, Is.EqualTo("mfa"));
            Assert.That(repository.LastSearchRequest?.Status, Is.EqualTo(CredentialStatus.Active));
            Assert.That(repository.LastSearchRequest?.Available, Is.True);
            Assert.That(repository.LastSearchRequest?.Revoked, Is.False);
            Assert.That(repository.LastSearchRequest?.CreatedFrom, Is.EqualTo(request.CreatedFrom));
            Assert.That(repository.LastSearchRequest?.CreatedTo, Is.EqualTo(request.CreatedTo));
            Assert.That(repository.LastSearchRequest?.UpdatedFrom, Is.EqualTo(request.UpdatedFrom));
            Assert.That(repository.LastSearchRequest?.UpdatedTo, Is.EqualTo(request.UpdatedTo));
            Assert.That(repository.LastSearchRequest?.LastUsedFrom, Is.EqualTo(request.LastUsedFrom));
            Assert.That(repository.LastSearchRequest?.LastUsedTo, Is.EqualTo(request.LastUsedTo));
            Assert.That(repository.LastSearchRequest?.ExpiresFrom, Is.EqualTo(request.ExpiresFrom));
            Assert.That(repository.LastSearchRequest?.ExpiresTo, Is.EqualTo(request.ExpiresTo));
            Assert.That(repository.LastSearchRequest?.Limit, Is.EqualTo(26));
        }
    }

    [Test]
    public async Task SearchCredentialsAsyncPassesTimeProviderTimestampForAvailability()
    {
        var expiringAtNow = CreateSummary(expiresAt: Now, isAvailable: false);
        var repository = new RecordingCredentialAdministrationRepository
        {
            SearchFactory = currentTime => new[]
            {
                expiringAtNow with { IsAvailable = expiringAtNow.ExpiresAt > currentTime }
            }
        };

        var result = await CreateService(repository).SearchCredentialsAsync(new SearchCredentialsRequest { IncludeAllTenants = true });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(repository.LastSearchNow, Is.EqualTo(Now));
            Assert.That(result.Value?.Items.Single().IsAvailable, Is.False);
        }
    }

    [Test]
    public async Task GetCredentialAsyncRejectsEmptyCredentialId()
    {
        var result = await CreateService().GetCredentialAsync(new CredentialAdministrationLookupRequest(Guid.Empty, TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public async Task GetCredentialAsyncMapsMissingCredentialSafely()
    {
        var result = await CreateService().GetCredentialAsync(new CredentialAdministrationLookupRequest(Guid.NewGuid(), TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.CredentialNotFound));
        }
    }

    [Test]
    public async Task GetCredentialAsyncReturnsRepositoryResult()
    {
        var expected = CreateSingleResult();
        var repository = new RecordingCredentialAdministrationRepository { GetResult = expected };

        var request = new CredentialAdministrationLookupRequest(expected.CredentialId, TenantContext.Global);
        var result = await CreateService(repository).GetCredentialAsync(request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value, Is.EqualTo(expected));
            Assert.That(repository.LastGetRequest, Is.SameAs(request));
            Assert.That(repository.LastGetNow, Is.EqualTo(Now));
        }
    }

    [Test]
    public async Task GetCredentialAsyncMapsOutOfScopeCredentialSafely()
    {
        var tenantId = Guid.NewGuid();
        var expected = CreateSingleResult() with { TenantId = tenantId };
        var repository = new RecordingCredentialAdministrationRepository { GetResult = expected };

        var result = await CreateService(repository).GetCredentialAsync(new CredentialAdministrationLookupRequest(expected.CredentialId, TenantContext.Global));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.CredentialNotFound));
    }

    [Test]
    public async Task GetCredentialAsyncAllowsExplicitAllTenantLookup()
    {
        var expected = CreateSingleResult() with { TenantId = Guid.NewGuid() };
        var repository = new RecordingCredentialAdministrationRepository { GetResult = expected };

        var result = await CreateService(repository).GetCredentialAsync(new CredentialAdministrationLookupRequest(expected.CredentialId, IncludeAllTenants: true));

        Assert.That(result.Value, Is.EqualTo(expected));
    }

    [Test]
    public async Task GetCredentialAsyncRejectsMissingAndConflictingTenantScope()
    {
        var service = CreateService();
        var credentialId = Guid.NewGuid();

        var missing = await service.GetCredentialAsync(new CredentialAdministrationLookupRequest(credentialId));
        var conflicting = await service.GetCredentialAsync(new CredentialAdministrationLookupRequest(credentialId, TenantContext.Global, IncludeAllTenants: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missing.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(conflicting.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public void CredentialAdministrationModelsDoNotExposeSensitiveStorageFields()
    {
        var forbidden = new[] { "CredentialValue", "ProviderKey", "Metadata", "Version", "PasswordHash", "TokenHash", "PasskeyPayload", "RecoveryCode" };
        var summaryProperties = typeof(CredentialAdministrationSummary).GetProperties().Select(static property => property.Name);
        var detailProperties = typeof(CredentialAdministrationSummary).GetProperties().Select(static property => property.Name);

        foreach (var property in forbidden)
        {
            using (Assert.EnterMultipleScope())
            {
                Assert.That(summaryProperties, Does.Not.Contain(property));
                Assert.That(detailProperties, Does.Not.Contain(property));
            }
        }
    }

    private static CredentialAdministrationService CreateService(RecordingCredentialAdministrationRepository? repository = null)
    {
        return new CredentialAdministrationService(repository ?? new RecordingCredentialAdministrationRepository(), new StaticTimeProvider(Now));
    }

    private static CredentialAdministrationSummary CreateSummary(DateTimeOffset? expiresAt = null, bool isAvailable = true)
    {
        return new CredentialAdministrationSummary(
            Guid.NewGuid(),
            Guid.NewGuid(),
            null,
            AuthenticationProviderKey.Local,
            "primary",
            CredentialStatus.Active,
            isAvailable,
            Now.AddDays(-1),
            null,
            null,
            expiresAt,
            null);
    }

    private static CredentialAdministrationSummary CreateSingleResult()
    {
        var summary = CreateSummary();
        return new CredentialAdministrationSummary(
            summary.CredentialId,
            summary.UserId,
            summary.TenantId,
            summary.Provider,
            summary.Purpose,
            summary.Status,
            summary.IsAvailable,
            summary.CreatedAt,
            summary.UpdatedAt,
            summary.LastUsedAt,
            summary.ExpiresAt,
            summary.RevokedAt);
    }

    private sealed class RecordingCredentialAdministrationRepository : ICredentialAdministrationRepository
    {
        public List<CredentialAdministrationSummary> SearchResults { get; } = [];
        public Func<DateTimeOffset, IReadOnlyList<CredentialAdministrationSummary>>? SearchFactory { get; init; }
        public SearchCredentialsRequest? LastSearchRequest { get; private set; }
        public DateTimeOffset? LastSearchNow { get; private set; }
        public CredentialAdministrationLookupRequest? LastGetRequest { get; private set; }
        public DateTimeOffset? LastGetNow { get; private set; }
        public CredentialAdministrationSummary? GetResult { get; init; }

        public Task<IReadOnlyList<CredentialAdministrationSummary>> SearchCredentialsAsync(SearchCredentialsRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            LastSearchRequest = request;
            LastSearchNow = now;
            return Task.FromResult(SearchFactory?.Invoke(now) ?? SearchResults.AsReadOnly());
        }

        public Task<CredentialAdministrationSummary?> GetCredentialAsync(CredentialAdministrationLookupRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
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
