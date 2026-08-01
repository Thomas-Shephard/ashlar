namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Provides read-only administrator user search and detail operations.
/// </summary>
/// <remarks>
/// Every operation enforces actor, active-session proof, scope, host authorization, and durable audit requirements.
/// </remarks>
public interface IUserAdministrationReader
{
    /// <summary>
    /// Searches users for administrator and operations interfaces.
    /// </summary>
    /// <param name="actor">Authenticated actor, active session, fresh proof, and audit metadata.</param>
    /// <param name="request">Tenant scope, filters, and paging options for the search.</param>
    /// <param name="cancellationToken">A token that can cancel the search.</param>
    /// <returns>Provider-neutral user summaries for administrative display.</returns>
    Task<Result<UserSearchResult>> SearchUsersAsync(AccountSecurityActorContext actor, SearchUsersRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets safe user detail with the existing security posture summary.
    /// </summary>
    /// <param name="actor">Authenticated actor, active session, fresh proof, and audit metadata.</param>
    /// <param name="request">Tenant scope and user identifier for the lookup.</param>
    /// <param name="cancellationToken">A token that can cancel the lookup.</param>
    /// <returns>Safe user detail and security posture information.</returns>
    Task<Result<UserAdministrationDetail>> GetUserDetailAsync(AccountSecurityActorContext actor, UserAdministrationLookupRequest request, CancellationToken cancellationToken = default);
}
