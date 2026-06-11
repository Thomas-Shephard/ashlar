namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Provides read-only administrator user search and detail operations.
/// </summary>
/// <remarks>
/// These operations are intended for administrative and operations tooling and do not authorize the caller.
/// Host applications must protect usage of this service with appropriate admin authorization and step-up policy.
/// </remarks>
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
    /// <param name="request">The detail request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result<UserAdministrationDetail>> GetUserDetailAsync(UserAdministrationDetailRequest request, CancellationToken cancellationToken = default);
}
