namespace Ashlar.Identity.Features.Administration;

/// <summary>
/// Implements read-only administrator user search and detail operations.
/// </summary>
/// <param name="repository">The repository value.</param>
/// <param name="accountSecurityService">The account security service value.</param>
/// <remarks>
/// Initializes a configured service instance.
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
    public async Task<Result<UserAdministrationDetail>> GetUserDetailAsync(Guid userId, UserSecurityPostureRequest? postureRequest = null, CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty)
        {
            return Result.Failure<UserAdministrationDetail>(AshlarFailureCodes.ValidationError, "User ID cannot be empty.");
        }

        var user = await _repository.GetUserSummaryAsync(userId, cancellationToken);
        if (user == null)
        {
            return Result.Failure<UserAdministrationDetail>(AshlarFailureCodes.UserNotFound);
        }

        var posture = await _accountSecurityService.GetUserSecurityPostureAsync(userId, postureRequest, cancellationToken);
        if (!posture.Succeeded || posture.Value == null)
        {
            return Result.Failure<UserAdministrationDetail>(posture.FailureDetails ?? new AshlarFailure(AshlarFailureCodes.UserNotFound));
        }

        return Result.Success(new UserAdministrationDetail(user, posture.Value));
    }
}
