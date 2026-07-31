using Ashlar.Auditing;

namespace Ashlar.Identity.Features.Administration;

internal sealed class UserAdministrationReader(IUserAdministrationRepository repository, IAccountSecurityPostureReader accountSecurityService,
    IAuthenticationSessionRepository sessions, IAccountSecurityOperationAuthorizer authorizer, IPersistentSecurityEventSink auditSink,
    TimeProvider? timeProvider = null) : IUserAdministrationReader
{
    internal const int MaximumLimit = 100;

    private readonly IUserAdministrationRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly IAccountSecurityPostureReader _accountSecurityService = accountSecurityService ?? throw new ArgumentNullException(nameof(accountSecurityService));
    private readonly AccountSecurityOperationBoundary _boundary = new(sessions, authorizer, auditSink, timeProvider ?? TimeProvider.System);

    public async Task<Result<UserSearchResult>> SearchUsersAsync(AccountSecurityActorContext actor, SearchUsersRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        ArgumentNullException.ThrowIfNull(request);

        if (!TryValidateSearchRequest(request, out var validationFailure))
        {
            await AuditValidationFailureAsync(actor, request.Tenant, request.IncludeAllTenants,
                AccountSecurityOperation.SearchUsers, cancellationToken);
            return validationFailure;
        }

        if (request.Offset < 0)
        {
            await AuditValidationFailureAsync(actor, request.Tenant, request.IncludeAllTenants,
                AccountSecurityOperation.SearchUsers, cancellationToken);
            return Result.Failure<UserSearchResult>(AshlarFailureCodes.ValidationError, "Offset cannot be negative.");
        }

        if (request.Limit < 1)
        {
            await AuditValidationFailureAsync(actor, request.Tenant, request.IncludeAllTenants,
                AccountSecurityOperation.SearchUsers, cancellationToken);
            return Result.Failure<UserSearchResult>(AshlarFailureCodes.ValidationError, "Limit must be greater than zero.");
        }

        if (await _boundary.AuthorizeAsync(actor, request.Tenant, request.IncludeAllTenants,
                Guid.Empty, AccountSecurityOperation.SearchUsers, cancellationToken) is { } authorizationFailure)
            return Result.Failure<UserSearchResult>(authorizationFailure);

        var limit = Math.Min(request.Limit, MaximumLimit);
        var repositoryRequest = request with { Limit = limit + 1 };
        List<UserSummary> users;
        try
        {
            users = (await _repository.SearchUsersAsync(repositoryRequest, cancellationToken)).ToList();
        }
        catch
        {
            await _boundary.RecordFailureAsync(actor, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.SearchUsers);
            throw;
        }
        if (users.Any(user => !IsValidSummary(user)
            || !AdministrationScopeValidation.IncludesResult(request.Tenant, request.IncludeAllTenants, user.TenantId)))
        {
            await _boundary.RecordFailureAsync(actor, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.SearchUsers);
            throw new InvalidOperationException("The user administration provider returned a result outside the authorized scope.");
        }
        await _boundary.RecordSuccessAsync(actor, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.SearchUsers);
        var hasMore = users.Count > limit;
        var page = users.Take(limit).ToList().AsReadOnly();

        return Result.Success(new UserSearchResult(page, limit, request.Offset, hasMore));
    }

    public async Task<Result<UserAdministrationDetail>> GetUserDetailAsync(AccountSecurityActorContext actor, UserAdministrationDetailRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        ArgumentNullException.ThrowIfNull(request);

        if (!TryValidateLookupRequest(request, out var validationFailure))
        {
            await AuditValidationFailureAsync(actor, request.Tenant, request.IncludeAllTenants,
                AccountSecurityOperation.ReadUser, cancellationToken);
            return validationFailure;
        }

        if (await _boundary.AuthorizeAsync(actor, request.Tenant, request.IncludeAllTenants,
                request.UserId, AccountSecurityOperation.ReadUser, cancellationToken) is { } authorizationFailure)
            return Result.Failure<UserAdministrationDetail>(authorizationFailure);

        UserSummary? user;
        try
        {
            user = await _repository.GetUserSummaryAsync(request, cancellationToken);
        }
        catch
        {
            await _boundary.RecordFailureAsync(actor, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.ReadUser);
            throw;
        }
        if (user == null || !IsValidSummary(user) || user.UserId != request.UserId
            || !AdministrationScopeValidation.IncludesResult(request.Tenant, request.IncludeAllTenants, user.TenantId))
        {
            await _boundary.RecordFailureAsync(actor, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.ReadUser);
            return Result.Failure<UserAdministrationDetail>(AshlarFailureCodes.UserNotFound);
        }

        Result<AccountSecurityPosture> posture;
        try
        {
            var postureRequest = new AccountSecurityPostureRequest(new TenantContext(user.TenantId), request.RecentSecurityEventWindow);
            posture = await _accountSecurityService.GetUserSecurityPostureAsync(request.UserId, postureRequest, cancellationToken);
        }
        catch
        {
            await _boundary.RecordFailureAsync(actor, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.ReadUser);
            throw;
        }
        if (!posture.Succeeded || posture.Value == null || posture.Value.UserId != user.UserId)
        {
            await _boundary.RecordFailureAsync(actor, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.ReadUser);
            return Result.Failure<UserAdministrationDetail>(posture.FailureDetails ?? new AshlarFailure(AshlarFailureCodes.UserNotFound));
        }
        await _boundary.RecordSuccessAsync(actor, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.ReadUser);
        return Result.Success(new UserAdministrationDetail(user, posture.Value));
    }

    private static bool TryValidateSearchRequest(SearchUsersRequest request, out Result<UserSearchResult> failure)
    {
        try
        {
            SearchUsersRequest.ThrowIfInvalid(request);
            failure = null!;
            return true;
        }
        catch (ArgumentException exception)
        {
            failure = Result.Failure<UserSearchResult>(AshlarFailureCodes.ValidationError, exception.Message);
            return false;
        }
    }

    private static bool IsValidSummary(UserSummary user) =>
        user.UserId != Guid.Empty && Enum.IsDefined(user.AccountState)
        && user.CanSignIn == user.AccountState.CanSignIn();

    private async Task AuditValidationFailureAsync(AccountSecurityActorContext actor, TenantContext? tenant,
        bool includeAllTenants, AccountSecurityOperation operation, CancellationToken cancellationToken)
    {
        await _boundary.RecordValidatedFailureAsync(actor, tenant, includeAllTenants, operation, cancellationToken);
    }

    private static bool TryValidateLookupRequest(UserAdministrationDetailRequest request, out Result<UserAdministrationDetail> failure)
    {
        try
        {
            UserAdministrationDetailRequest.ThrowIfInvalid(request);
            failure = null!;
            return true;
        }
        catch (ArgumentException exception)
        {
            failure = Result.Failure<UserAdministrationDetail>(AshlarFailureCodes.ValidationError, exception.Message);
            return false;
        }
    }
}
