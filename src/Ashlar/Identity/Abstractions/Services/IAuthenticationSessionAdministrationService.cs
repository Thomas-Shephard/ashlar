namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Provides read-only administrator authentication session browsing operations.
/// </summary>
/// <remarks>
/// Every operation enforces actor, active-session proof, scope, host authorization, and durable audit requirements.
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
    /// <returns>The same provider-neutral session projection used by search when found. Raw bearer tokens are never returned.</returns>
    Task<Result<AuthenticationSessionAdministrationSummary>> GetAuthenticationSessionAsync(AuthenticationSessionAdministrationLookupRequest request, CancellationToken cancellationToken = default);
}
