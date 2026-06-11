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
    /// <param name="request">The search request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result<AuthenticationSessionSearchResult>> SearchAuthenticationSessionsAsync(SearchAuthenticationSessionsRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets an authentication session by id.
    /// </summary>
    /// <param name="request">The detail request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result<AuthenticationSessionAdministrationDetail>> GetAuthenticationSessionAsync(AuthenticationSessionAdministrationDetailRequest request, CancellationToken cancellationToken = default);
}
