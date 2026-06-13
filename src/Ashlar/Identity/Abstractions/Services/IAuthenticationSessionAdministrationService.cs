namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Provides read-only administrator authentication session browsing operations.
/// </summary>
/// <remarks>
/// These operations are intended for administrative and operations tooling and do not authorize the caller.
/// Host applications must protect usage of this service with appropriate admin authorization and step-up policy.
/// </remarks>
public interface IAuthenticationSessionAdministrationService
{
    /// <summary>
    /// Searches authentication sessions using provider-neutral display fields.
    /// </summary>
    /// <param name="request">Tenant scope, filters, and paging options for the search.</param>
    /// <param name="cancellationToken">A token that can cancel the search.</param>
    /// <returns>Provider-neutral session summaries. Raw bearer tokens are never returned.</returns>
    Task<Result<AuthenticationSessionSearchResult>> SearchAuthenticationSessionsAsync(SearchAuthenticationSessionsRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets an authentication session by id.
    /// </summary>
    /// <param name="request">Tenant scope and session identifier for the lookup.</param>
    /// <param name="cancellationToken">A token that can cancel the lookup.</param>
    /// <returns>The session detail when found. Raw bearer tokens are never returned.</returns>
    Task<Result<AuthenticationSessionAdministrationDetail>> GetAuthenticationSessionAsync(AuthenticationSessionAdministrationDetailRequest request, CancellationToken cancellationToken = default);
}
