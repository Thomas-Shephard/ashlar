namespace Ashlar.Identity.Abstractions.Repositories;

/// <summary>
/// Provides read-only administrator user lookup operations.
/// </summary>
public interface IUserAdministrationRepository
{
    /// <summary>
    /// Searches users using safe administrator-display fields.
    /// </summary>
    /// <param name="request">Search filters and tenant scope supplied by an authorized administrator flow.</param>
    /// <param name="cancellationToken">A token that can cancel the search.</param>
    /// <returns>The matching safe user summaries.</returns>
    Task<IReadOnlyList<UserSummary>> SearchUsersAsync(SearchUsersRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets a user summary by id.
    /// </summary>
    /// <param name="request">User identifier and tenant scope supplied by an authorized administrator flow.</param>
    /// <param name="cancellationToken">A token that can cancel lookup.</param>
    /// <returns>The safe user summary, or <see langword="null" /> when no user matches.</returns>
    Task<UserSummary?> GetUserSummaryAsync(UserAdministrationLookupRequest request, CancellationToken cancellationToken = default);
}
