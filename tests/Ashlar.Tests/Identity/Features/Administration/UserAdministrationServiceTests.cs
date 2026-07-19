namespace Ashlar.Tests.Identity.Features.Administration;

using Ashlar.Tests.Support;

internal sealed class UserAdministrationServiceTests
{
    [Test]
    public void SearchUsersAsyncRejectsNullRequest()
    {
        var service = CreateService();

        Assert.ThrowsAsync<ArgumentNullException>(async () => await service.SearchUsersAsync(null!));
    }

    [Test]
    public void ConstructorRejectsNullDependencies()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => new UserAdministrationService(null!, new RecordingAccountSecurityService(), null!, null!, null!));
            Assert.Throws<ArgumentNullException>(() => new UserAdministrationService(new RecordingUserAdministrationRepository(), null!, null!, null!, null!));
        }
    }

    [TestCase(0)]
    [TestCase(-1)]
    public async Task SearchUsersAsyncRejectsInvalidLimit(int limit)
    {
        var service = CreateService();

        var result = await service.SearchUsersAsync(new SearchUsersRequest { IncludeAllTenants = true, Limit = limit });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public async Task SearchUsersAsyncRejectsNegativeOffset()
    {
        var service = CreateService();

        var result = await service.SearchUsersAsync(new SearchUsersRequest { IncludeAllTenants = true, Limit = 10, Offset = -1 });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public async Task SearchUsersAsyncCapsLimitAndUsesExtraRowForHasMore()
    {
        var repository = new RecordingUserAdministrationRepository();
        for (var i = 0; i < 101; i++)
        {
            repository.SearchResults.Add(CreateSummary($"user{i:D3}@example.com"));
        }

        var service = CreateService(repository);

        var result = await service.SearchUsersAsync(new SearchUsersRequest { IncludeAllTenants = true, Limit = 500, Offset = 2, Query = "user" });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.Limit, Is.EqualTo(100));
            Assert.That(result.Value?.Offset, Is.EqualTo(2));
            Assert.That(result.Value?.HasMore, Is.True);
            Assert.That(result.Value?.Items, Has.Count.EqualTo(100));
            Assert.That(repository.LastSearchRequest?.Limit, Is.EqualTo(101));
            Assert.That(repository.LastSearchRequest?.Offset, Is.EqualTo(2));
            Assert.That(repository.LastSearchRequest?.Query, Is.EqualTo("user"));
        }
    }

    [Test]
    public async Task SearchUsersAsyncDelegatesRequestAndPreservesTenantScope()
    {
        var tenant = new TenantContext(Guid.NewGuid());
        var repository = new RecordingUserAdministrationRepository();
        var expected = CreateSummary("tenant@example.com", tenant.TenantId);
        repository.SearchResults.Add(expected);
        var service = CreateService(repository);

        var result = await service.SearchUsersAsync(new SearchUsersRequest
        {
            Query = "tenant",
            Tenant = tenant,
            AccountState = UserAccountState.Active,
            IsEmailVerified = false,
            Limit = 25,
            Offset = 5
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.Items.Single(), Is.EqualTo(expected));
            Assert.That(repository.LastSearchRequest?.Tenant, Is.SameAs(tenant));
            Assert.That(repository.LastSearchRequest?.AccountState, Is.EqualTo(UserAccountState.Active));
            Assert.That(repository.LastSearchRequest?.IsEmailVerified, Is.False);
            Assert.That(repository.LastSearchRequest?.Limit, Is.EqualTo(26));
        }
    }

    [Test]
    public async Task GetUserDetailAsyncReturnsUserDetailWithPosture()
    {
        var userId = Guid.NewGuid();
        var repository = new RecordingUserAdministrationRepository { UserSummary = CreateSummary("detail@example.com") with { UserId = userId } };
        var posture = CreatePosture(userId);
        var accountSecurity = new RecordingAccountSecurityService { PostureResult = Result.Success(posture) };
        var eventWindow = TimeSpan.FromDays(7);
        var detailRequest = new UserAdministrationDetailRequest(userId, TenantContext.Global, RecentSecurityEventWindow: eventWindow);
        var service = CreateService(repository, accountSecurity);

        var result = await service.GetUserDetailAsync(detailRequest);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.User.UserId, Is.EqualTo(userId));
            Assert.That(result.Value?.SecurityPosture, Is.SameAs(posture));
            Assert.That(accountSecurity.LastPostureUserId, Is.EqualTo(userId));
            Assert.That(repository.LastGetRequest, Is.EqualTo(detailRequest));
            Assert.That(accountSecurity.LastPostureRequest?.Tenant, Is.EqualTo(TenantContext.Global));
            Assert.That(accountSecurity.LastPostureRequest?.RecentSecurityEventWindow, Is.EqualTo(eventWindow));
        }
    }

    [Test]
    public async Task GetUserDetailAsyncReturnsTenantScopedUserDetailWithPosture()
    {
        var tenantId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        var repository = new RecordingUserAdministrationRepository { UserSummary = CreateSummary("tenant-detail@example.com", tenantId) with { UserId = userId } };
        var posture = CreatePosture(userId);
        var accountSecurity = new RecordingAccountSecurityService { PostureResult = Result.Success(posture) };
        var service = CreateService(repository, accountSecurity);

        var result = await service.GetUserDetailAsync(new UserAdministrationDetailRequest(userId, new TenantContext(tenantId)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value?.SecurityPosture, Is.SameAs(posture));
            Assert.That(accountSecurity.LastPostureRequest?.Tenant, Is.EqualTo(new TenantContext(tenantId)));
        }
    }

    [Test]
    public async Task SearchUsersAsyncRejectsMissingAndConflictingTenantScope()
    {
        var service = CreateService();

        var missing = await service.SearchUsersAsync(new SearchUsersRequest { Limit = 10 });
        var conflicting = await service.SearchUsersAsync(new SearchUsersRequest { Tenant = TenantContext.Global, IncludeAllTenants = true, Limit = 10 });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missing.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(conflicting.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public async Task GetUserDetailAsyncReturnsNotFoundWhenUserIsMissing()
    {
        var accountSecurity = new RecordingAccountSecurityService();
        var service = CreateService(new RecordingUserAdministrationRepository(), accountSecurity);

        var result = await service.GetUserDetailAsync(new UserAdministrationDetailRequest(Guid.NewGuid(), TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(accountSecurity.PostureCalls, Is.Zero);
        }
    }

    [Test]
    public async Task GetUserDetailAsyncMapsPostureFailure()
    {
        var userId = Guid.NewGuid();
        var repository = new RecordingUserAdministrationRepository { UserSummary = CreateSummary("detail@example.com") with { UserId = userId } };
        var accountSecurity = new RecordingAccountSecurityService
        {
            PostureResult = Result.Failure<AccountSecurityPosture>(AshlarFailureCodes.UserNotFound)
        };
        var service = CreateService(repository, accountSecurity);

        var result = await service.GetUserDetailAsync(new UserAdministrationDetailRequest(userId, TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
        }
    }

    [Test]
    public async Task GetUserDetailAsyncMapsNullPostureValueToNotFound()
    {
        var userId = Guid.NewGuid();
        var repository = new RecordingUserAdministrationRepository { UserSummary = CreateSummary("detail@example.com") with { UserId = userId } };
        var accountSecurity = new RecordingAccountSecurityService
        {
            PostureResult = new Result<AccountSecurityPosture>(true)
        };
        var service = CreateService(repository, accountSecurity);

        var result = await service.GetUserDetailAsync(new UserAdministrationDetailRequest(userId, TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
        }
    }

    [Test]
    public async Task GetUserDetailAsyncRejectsEmptyUserId()
    {
        var service = CreateService();

        var result = await service.GetUserDetailAsync(new UserAdministrationDetailRequest(Guid.Empty, TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public async Task GetUserDetailAsyncReturnsNotFoundWhenRepositoryReturnsOutOfScopeUser()
    {
        var tenantId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        var repository = new RecordingUserAdministrationRepository { UserSummary = CreateSummary("out-of-scope@example.com", tenantId) with { UserId = userId } };
        var accountSecurity = new RecordingAccountSecurityService { PostureResult = Result.Success(CreatePosture(userId)) };
        var service = CreateService(repository, accountSecurity);

        var result = await service.GetUserDetailAsync(new UserAdministrationDetailRequest(userId, TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(accountSecurity.PostureCalls, Is.Zero);
        }
    }

    [Test]
    public async Task GetUserDetailAsyncReturnsNotFoundWhenTenantScopeRequestsGlobalUser()
    {
        var tenantId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        var repository = new RecordingUserAdministrationRepository { UserSummary = CreateSummary("global-user@example.com") with { UserId = userId } };
        var accountSecurity = new RecordingAccountSecurityService { PostureResult = Result.Success(CreatePosture(userId)) };
        var service = CreateService(repository, accountSecurity);

        var result = await service.GetUserDetailAsync(new UserAdministrationDetailRequest(userId, new TenantContext(tenantId)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(accountSecurity.PostureCalls, Is.Zero);
        }
    }

    [Test]
    public async Task GetUserDetailAsyncAllowsExplicitAllTenantDetail()
    {
        var tenantId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        var repository = new RecordingUserAdministrationRepository { UserSummary = CreateSummary("all-tenant@example.com", tenantId) with { UserId = userId } };
        var posture = CreatePosture(userId);
        var accountSecurity = new RecordingAccountSecurityService { PostureResult = Result.Success(posture) };
        var service = CreateService(repository, accountSecurity);

        var result = await service.GetUserDetailAsync(new UserAdministrationDetailRequest(userId, IncludeAllTenants: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value?.SecurityPosture, Is.SameAs(posture));
            Assert.That(accountSecurity.LastPostureRequest?.Tenant, Is.EqualTo(new TenantContext(tenantId)));
        }
    }

    [Test]
    public async Task GetUserDetailAsyncRejectsMissingAndConflictingTenantScope()
    {
        var service = CreateService();
        var userId = Guid.NewGuid();

        var missing = await service.GetUserDetailAsync(new UserAdministrationDetailRequest(userId));
        var conflicting = await service.GetUserDetailAsync(new UserAdministrationDetailRequest(userId, TenantContext.Global, IncludeAllTenants: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missing.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(conflicting.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public void SearchUsersAsyncAuditsProviderFailure()
    {
        var repository = new RecordingUserAdministrationRepository { SearchException = new InvalidOperationException() };

        Assert.ThrowsAsync<InvalidOperationException>(() => CreateService(repository).SearchUsersAsync(
            new SearchUsersRequest { Tenant = TenantContext.Global }));
    }

    [Test]
    public void SearchUsersAsyncRejectsOutOfScopePaginationSentinel()
    {
        var tenant = new TenantContext(Guid.NewGuid());
        var repository = new RecordingUserAdministrationRepository();
        repository.SearchResults.Add(CreateSummary("allowed@example.com", tenant.TenantId));
        repository.SearchResults.Add(CreateSummary("hidden@example.com", Guid.NewGuid()));

        Assert.ThrowsAsync<InvalidOperationException>(() => CreateService(repository).SearchUsersAsync(
            new SearchUsersRequest { Tenant = tenant, Limit = 1 }));
    }

    [Test]
    public async Task GetUserDetailAsyncRejectsMismatchedProviderIdentities()
    {
        var requestedUserId = Guid.NewGuid();
        var returnedUserId = Guid.NewGuid();
        var repository = new RecordingUserAdministrationRepository
        {
            UserSummary = CreateSummary("wrong@example.com") with { UserId = returnedUserId }
        };
        var wrongUser = await CreateService(repository).GetUserDetailAsync(
            new UserAdministrationDetailRequest(requestedUserId, TenantContext.Global));

        repository = new RecordingUserAdministrationRepository
        {
            UserSummary = CreateSummary("right@example.com") with { UserId = requestedUserId }
        };
        var accountSecurity = new RecordingAccountSecurityService { PostureResult = Result.Success(CreatePosture(returnedUserId)) };
        var wrongPosture = await CreateService(repository, accountSecurity).GetUserDetailAsync(
            new UserAdministrationDetailRequest(requestedUserId, TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(wrongUser.Succeeded, Is.False);
            Assert.That(wrongPosture.Succeeded, Is.False);
        }
    }

    private static AuthorizedUserAdministrationService CreateService(
        RecordingUserAdministrationRepository? repository = null,
        RecordingAccountSecurityService? accountSecurityService = null)
    {
        var boundary = new AdminReadTestBoundary(DateTimeOffset.UtcNow);
        return new AuthorizedUserAdministrationService(new UserAdministrationService(
            repository ?? new RecordingUserAdministrationRepository(),
            accountSecurityService ?? new RecordingAccountSecurityService(), boundary.Sessions,
            boundary.Authorizer, boundary.Sink, boundary.TimeProvider), boundary.Actor);
    }

    private sealed class AuthorizedUserAdministrationService(UserAdministrationService service, AccountSecurityActorContext actor)
    {
        public Task<Result<UserSearchResult>> SearchUsersAsync(SearchUsersRequest request) =>
            service.SearchUsersAsync(request is null ? null! : request with { Actor = actor });
        public Task<Result<UserAdministrationDetail>> GetUserDetailAsync(UserAdministrationDetailRequest request) =>
            service.GetUserDetailAsync(request with { Actor = actor });
    }

    private static UserSummary CreateSummary(string email, Guid? tenantId = null)
    {
        return new UserSummary(Guid.NewGuid(), email, "Test User", tenantId, UserAccountState.Active, true, true, DateTimeOffset.UtcNow, null);
    }

    private static AccountSecurityPosture CreatePosture(Guid userId)
    {
        return new AccountSecurityPosture(
            userId,
            UserAccountState.Active,
            true,
            true,
            [],
            [],
            new AccountSecurityPolicyPosture(false, [], [], false, true, [], [], false),
            [],
            0,
            null);
    }

    private sealed class RecordingUserAdministrationRepository : IUserAdministrationRepository
    {
        public List<UserSummary> SearchResults { get; } = [];
        public SearchUsersRequest? LastSearchRequest { get; private set; }
        public UserAdministrationDetailRequest? LastGetRequest { get; private set; }
        public UserSummary? UserSummary { get; init; }
        public Exception? SearchException { get; init; }

        public Task<IReadOnlyList<UserSummary>> SearchUsersAsync(SearchUsersRequest request, CancellationToken cancellationToken = default)
        {
            if (SearchException is not null) throw SearchException;
            LastSearchRequest = request;
            return Task.FromResult<IReadOnlyList<UserSummary>>(SearchResults.AsReadOnly());
        }

        public Task<UserSummary?> GetUserSummaryAsync(UserAdministrationDetailRequest request, CancellationToken cancellationToken = default)
        {
            LastGetRequest = request;
            return Task.FromResult(UserSummary);
        }
    }

    private sealed class RecordingAccountSecurityService : IAccountSecurityService
    {
        public Result<AccountSecurityPosture> PostureResult { get; init; } = Result.Failure<AccountSecurityPosture>(AshlarFailureCodes.UserNotFound);
        public int PostureCalls { get; private set; }
        public Guid LastPostureUserId { get; private set; }
        public AccountSecurityPostureRequest? LastPostureRequest { get; private set; }

        public Task<Result<AccountSecurityPosture>> GetUserSecurityPostureAsync(Guid userId, AccountSecurityPostureRequest? request = null, CancellationToken cancellationToken = default)
        {
            PostureCalls++;
            LastPostureUserId = userId;
            LastPostureRequest = request;
            return Task.FromResult(PostureResult);
        }
    }
}
