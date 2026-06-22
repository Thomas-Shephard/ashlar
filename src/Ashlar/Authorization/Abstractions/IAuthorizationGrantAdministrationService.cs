using Ashlar.Authorization.Models;

namespace Ashlar.Authorization.Abstractions;

/// <summary>
/// Provides read-only administrator authorization grant browsing operations.
/// </summary>
/// <remarks>
/// These operations are intended for administrative and operations tooling and do not authorize the caller.
/// Host applications must protect usage of this service with appropriate admin authorization and fresh step-up policy.
/// Raw grant metadata is not returned because metadata is application-defined and may not be safe for broad display.
/// </remarks>
public interface IAuthorizationGrantAdministrationService
{
    /// <summary>
    /// Searches authorization grants using provider-neutral display fields.
    /// </summary>
    /// <param name="request">Tenant scope, filters, and paging options for the search.</param>
    /// <param name="cancellationToken">A token that can cancel the search.</param>
    /// <returns>Provider-neutral grant summaries without raw metadata.</returns>
    Task<Result<AuthorizationGrantSearchResult>> SearchAuthorizationGrantsAsync(SearchAuthorizationGrantsRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets an authorization grant by id.
    /// </summary>
    /// <param name="request">Tenant scope and grant identifier for the lookup.</param>
    /// <param name="cancellationToken">A token that can cancel the lookup.</param>
    /// <returns>The same provider-neutral grant projection used by search when found, without raw metadata.</returns>
    Task<Result<AuthorizationGrantAdministrationSummary>> GetAuthorizationGrantAsync(AuthorizationGrantAdministrationLookupRequest request, CancellationToken cancellationToken = default);
}
