using Ashlar.Auditing;

namespace Ashlar.Identity.Features.Administration;

/// <summary>
/// Implements read-only administrator user search and detail operations.
/// </summary>
/// <param name="repository">Repository used for safe administrator user lookup.</param>
/// <param name="accountSecurityService">Service used to attach account security posture details.</param>
/// <param name="sessions">Authoritative session repository.</param>
/// <param name="authorizer">Required host authorization policy.</param>
/// <param name="auditSink">Required durable audit sink.</param>
/// <param name="timeProvider">Clock used for proof validation and auditing.</param>
/// <remarks>
/// Every operation enforces actor-bound active-session proof, scope, host authorization, and durable audit requirements.
/// </remarks>
public sealed class UserAdministrationService(IUserAdministrationRepository repository, IAccountSecurityService accountSecurityService,
    IAuthenticationSessionRepository sessions, IAccountSecurityOperationAuthorizer authorizer, IPersistentSecurityEventSink auditSink,
    TimeProvider? timeProvider = null) : IUserAdministrationService
{
    internal const int MaximumLimit = 100;

    private readonly IUserAdministrationRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly IAccountSecurityService _accountSecurityService = accountSecurityService ?? throw new ArgumentNullException(nameof(accountSecurityService));
    private readonly AdminReadBoundary _boundary = new(sessions, authorizer, auditSink, timeProvider ?? TimeProvider.System);


    /// <inheritdoc />
    public async Task<Result<UserSearchResult>> SearchUsersAsync(SearchUsersRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!TryValidateSearchRequest(request, out var validationFailure))
        {
            return validationFailure;
        }

        if (request.Offset < 0)
        {
            return Result.Failure<UserSearchResult>(AshlarFailureCodes.ValidationError, "Offset cannot be negative.");
        }

        if (request.Limit < 1)
        {
            return Result.Failure<UserSearchResult>(AshlarFailureCodes.ValidationError, "Limit must be greater than zero.");
        }

        if (!await _boundary.AuthorizeAsync(request.Actor, request.Tenant, request.IncludeAllTenants,
                Guid.Empty, AccountSecurityOperation.SearchUsers, cancellationToken,
                recordSuccess: false))
            return Result.Failure<UserSearchResult>(AshlarFailureCodes.ValidationError);

        var limit = Math.Min(request.Limit, MaximumLimit);
        var repositoryRequest = request with { Actor = null, Limit = limit + 1 };
        List<UserSummary> users;
        try
        {
            users = (await _repository.SearchUsersAsync(repositoryRequest, cancellationToken)).ToList();
        }
        catch
        {
            await _boundary.RecordFailureAsync(request.Actor!, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.SearchUsers);
            throw;
        }
        if (users.Any(user => !AdministrationScopeValidation.IncludesResult(request.Tenant, request.IncludeAllTenants, user.TenantId)))
        {
            await _boundary.RecordFailureAsync(request.Actor!, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.SearchUsers);
            throw new InvalidOperationException("The user administration provider returned a result outside the authorized scope.");
        }
        await _boundary.RecordSuccessAsync(request.Actor!, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.SearchUsers);
        var hasMore = users.Count > limit;
        var page = users.Take(limit).ToList().AsReadOnly();

        return Result.Success(new UserSearchResult(page, limit, request.Offset, hasMore));
    }

    /// <inheritdoc />
    public async Task<Result<UserAdministrationDetail>> GetUserDetailAsync(UserAdministrationDetailRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!TryValidateLookupRequest(request, out var validationFailure))
        {
            return validationFailure;
        }

        if (!await _boundary.AuthorizeAsync(request.Actor, request.Tenant, request.IncludeAllTenants,
                request.UserId, AccountSecurityOperation.ReadUser, cancellationToken, recordSuccess: false))
            return Result.Failure<UserAdministrationDetail>(AshlarFailureCodes.ValidationError);

        UserSummary? user;
        try
        {
            user = await _repository.GetUserSummaryAsync(request with { Actor = null }, cancellationToken);
        }
        catch
        {
            await _boundary.RecordFailureAsync(request.Actor!, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.ReadUser);
            throw;
        }
        if (user == null || user.UserId != request.UserId
            || !AdministrationScopeValidation.IncludesResult(request.Tenant, request.IncludeAllTenants, user.TenantId))
        {
            await _boundary.RecordFailureAsync(request.Actor!, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.ReadUser);
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
            await _boundary.RecordFailureAsync(request.Actor!, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.ReadUser);
            throw;
        }
        if (!posture.Succeeded || posture.Value == null || posture.Value.UserId != user.UserId)
        {
            await _boundary.RecordFailureAsync(request.Actor!, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.ReadUser);
            return Result.Failure<UserAdministrationDetail>(posture.FailureDetails ?? new AshlarFailure(AshlarFailureCodes.UserNotFound));
        }
        await _boundary.RecordSuccessAsync(request.Actor!, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.ReadUser);
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
