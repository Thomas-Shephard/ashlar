namespace Ashlar.Identity.Abstractions.Repositories;

/// <summary>
/// Provides read-only administrator user lookup operations.
/// </summary>
public interface IUserAdministrationRepository
{
    /// <summary>
    /// Searches users using safe administrator-display fields.
    /// </summary>
    /// <param name="request">The search request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<IReadOnlyList<UserSummary>> SearchUsersAsync(SearchUsersRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets a user summary by id.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<UserSummary?> GetUserSummaryAsync(Guid userId, CancellationToken cancellationToken = default);
}
