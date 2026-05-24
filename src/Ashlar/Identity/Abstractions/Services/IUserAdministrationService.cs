namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Provides read-only administrator user search and detail operations.
/// </summary>
public interface IUserAdministrationService
{
    /// <summary>
    /// Searches users for administrator and operations interfaces.
    /// </summary>
    /// <param name="request">The search request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result<UserSearchResult>> SearchUsersAsync(SearchUsersRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets safe user detail with the existing security posture summary.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="postureRequest">The posture request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result<UserAdministrationDetail>> GetUserDetailAsync(Guid userId, UserSecurityPostureRequest? postureRequest = null, CancellationToken cancellationToken = default);
}
