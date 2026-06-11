namespace Ashlar.Identity.Features.Administration;

/// <summary>
/// Implements read-only administrator user search and detail operations.
/// </summary>
/// <param name="repository">The repository value.</param>
/// <param name="accountSecurityService">The account security service value.</param>
/// <remarks>
/// These operations are intended for administrative diagnostics and operations tooling and do not authorize the caller.
/// Host applications must protect usage of this service with appropriate admin authorization and step-up policy.
/// </remarks>
public sealed class UserAdministrationService(IUserAdministrationRepository repository, IAccountSecurityService accountSecurityService) : IUserAdministrationService
{
    internal const int MaximumLimit = 100;

    private readonly IUserAdministrationRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly IAccountSecurityService _accountSecurityService = accountSecurityService ?? throw new ArgumentNullException(nameof(accountSecurityService));


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

        var limit = Math.Min(request.Limit, MaximumLimit);
        var repositoryRequest = request with { Limit = limit + 1 };
        var users = await _repository.SearchUsersAsync(repositoryRequest, cancellationToken);
        var hasMore = users.Count > limit;
        var page = users.Take(limit).ToList().AsReadOnly();

        return Result.Success(new UserSearchResult(page, limit, request.Offset, hasMore));
    }

    /// <inheritdoc />
    public async Task<Result<UserAdministrationDetail>> GetUserDetailAsync(UserAdministrationDetailRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!TryValidateDetailRequest(request, out var validationFailure))
        {
            return validationFailure;
        }

        var user = await _repository.GetUserSummaryAsync(request, cancellationToken);
        if (user == null || (!request.IncludeAllTenants && !AdministrationScopeValidation.IncludesTenant(request.Tenant!, user.TenantId)))
        {
            return Result.Failure<UserAdministrationDetail>(AshlarFailureCodes.UserNotFound);
        }

        var postureRequest = new UserSecurityPostureRequest(new TenantContext(user.TenantId), request.RecentSecurityEventWindow);
        var posture = await _accountSecurityService.GetUserSecurityPostureAsync(request.UserId, postureRequest, cancellationToken);
        if (!posture.Succeeded || posture.Value == null)
        {
            return Result.Failure<UserAdministrationDetail>(posture.FailureDetails ?? new AshlarFailure(AshlarFailureCodes.UserNotFound));
        }

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

    private static bool TryValidateDetailRequest(UserAdministrationDetailRequest request, out Result<UserAdministrationDetail> failure)
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
