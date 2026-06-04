namespace Ashlar.Tests.Identity.Features.Administration;

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
            Assert.Throws<ArgumentNullException>(() => new UserAdministrationService(null!, new RecordingAccountSecurityService()));
            Assert.Throws<ArgumentNullException>(() => new UserAdministrationService(new RecordingUserAdministrationRepository(), null!));
        }
    }

    [TestCase(0)]
    [TestCase(-1)]
    public async Task SearchUsersAsyncRejectsInvalidLimit(int limit)
    {
        var service = CreateService();

        var result = await service.SearchUsersAsync(new SearchUsersRequest { Limit = limit });

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

        var result = await service.SearchUsersAsync(new SearchUsersRequest { Limit = 10, Offset = -1 });

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

        var result = await service.SearchUsersAsync(new SearchUsersRequest { Limit = 500, Offset = 2, Query = "user" });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.Limit, Is.EqualTo(100));
            Assert.That(result.Value?.Offset, Is.EqualTo(2));
            Assert.That(result.Value?.HasMore, Is.True);
            Assert.That(result.Value?.Users, Has.Count.EqualTo(100));
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
            Assert.That(result.Value?.Users.Single(), Is.EqualTo(expected));
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
        var request = new UserSecurityPostureRequest(TenantContext.Global);
        var service = CreateService(repository, accountSecurity);

        var result = await service.GetUserDetailAsync(userId, request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.User.UserId, Is.EqualTo(userId));
            Assert.That(result.Value?.SecurityPosture, Is.SameAs(posture));
            Assert.That(accountSecurity.LastPostureUserId, Is.EqualTo(userId));
            Assert.That(accountSecurity.LastPostureRequest, Is.SameAs(request));
        }
    }

    [Test]
    public async Task GetUserDetailAsyncReturnsNotFoundWhenUserIsMissing()
    {
        var accountSecurity = new RecordingAccountSecurityService();
        var service = CreateService(new RecordingUserAdministrationRepository(), accountSecurity);

        var result = await service.GetUserDetailAsync(Guid.NewGuid());

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
            PostureResult = Result.Failure<UserSecurityPosture>(AshlarFailureCodes.UserNotFound)
        };
        var service = CreateService(repository, accountSecurity);

        var result = await service.GetUserDetailAsync(userId);

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
            PostureResult = new Result<UserSecurityPosture>(true)
        };
        var service = CreateService(repository, accountSecurity);

        var result = await service.GetUserDetailAsync(userId);

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

        var result = await service.GetUserDetailAsync(Guid.Empty);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    private static UserAdministrationService CreateService(
        RecordingUserAdministrationRepository? repository = null,
        RecordingAccountSecurityService? accountSecurityService = null)
    {
        return new UserAdministrationService(
            repository ?? new RecordingUserAdministrationRepository(),
            accountSecurityService ?? new RecordingAccountSecurityService());
    }

    private static UserSummary CreateSummary(string email, Guid? tenantId = null)
    {
        return new UserSummary(Guid.NewGuid(), email, "Test User", tenantId, UserAccountState.Active, true, true, DateTimeOffset.UtcNow, null);
    }

    private static UserSecurityPosture CreatePosture(Guid userId)
    {
        return new UserSecurityPosture(
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
        public UserSummary? UserSummary { get; init; }

        public Task<IReadOnlyList<UserSummary>> SearchUsersAsync(SearchUsersRequest request, CancellationToken cancellationToken = default)
        {
            LastSearchRequest = request;
            return Task.FromResult<IReadOnlyList<UserSummary>>(SearchResults.AsReadOnly());
        }

        public Task<UserSummary?> GetUserSummaryAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(UserSummary);
        }
    }

    private sealed class RecordingAccountSecurityService : IAccountSecurityService
    {
        public Result<UserSecurityPosture> PostureResult { get; init; } = Result.Failure<UserSecurityPosture>(AshlarFailureCodes.UserNotFound);
        public int PostureCalls { get; private set; }
        public Guid LastPostureUserId { get; private set; }
        public UserSecurityPostureRequest? LastPostureRequest { get; private set; }

        public Task<Result<AccountSecurityOperationResult>> DisableUserAsync(Guid userId, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task<Result<AccountSecurityOperationResult>> ReactivateUserAsync(Guid userId, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task<Result<AccountSecurityOperationResult>> RevokeSessionsAsync(Guid userId, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task<Result<AccountSecurityOperationResult>> RevokeCredentialsAsync(Guid userId, AuthenticationProviderKey provider, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task<Result<AccountSecurityOperationResult>> ResetMfaAsync(Guid userId, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task<Result<UserSecurityPosture>> GetUserSecurityPostureAsync(Guid userId, UserSecurityPostureRequest? request = null, CancellationToken cancellationToken = default)
        {
            PostureCalls++;
            LastPostureUserId = userId;
            LastPostureRequest = request;
            return Task.FromResult(PostureResult);
        }
    }
}
