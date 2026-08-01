using Ashlar.Authorization.Models;

namespace Ashlar.Authorization.Abstractions;

/// <summary>
/// Provides read-only administrator authorization grant browsing operations.
/// </summary>
/// <remarks>
/// Every operation requires an explicit tenant, global, or all-tenant scope, an Ashlar-issued purpose-bound fresh MFA proof,
/// its active source session, actor-bound audit identity, and approval from the configured host authorizer.
/// Grant reads use the shared administration-read proof contract and durably audit normalized success and failure events.
/// Audit persistence failures fail closed. Grant mutations retain their separate purpose-bound contract.
/// Raw grant metadata is not returned because metadata is application-defined and may not be safe for broad display.
/// </remarks>
public interface IAuthorizationGrantAdministrationService
{
    /// <summary>
    /// Searches authorization grants using provider-neutral display fields.
    /// </summary>
    /// <param name="actor">Verified actor, active session, purpose-bound proof, and audit context.</param>
    /// <param name="request">Tenant scope, filters, and paging options for the search.</param>
    /// <param name="cancellationToken">A token that can cancel the search.</param>
    /// <returns>Provider-neutral grant summaries without raw metadata.</returns>
    Task<Result<AuthorizationGrantSearchResult>> SearchAuthorizationGrantsAsync(AccountSecurityActorContext actor, SearchAuthorizationGrantsRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets an authorization grant by id.
    /// </summary>
    /// <param name="actor">Verified actor, active session, purpose-bound proof, and audit context.</param>
    /// <param name="request">Tenant scope and grant identifier for the lookup.</param>
    /// <param name="cancellationToken">A token that can cancel the lookup.</param>
    /// <returns>The same provider-neutral grant projection used by search when found, without raw metadata.</returns>
    Task<Result<AuthorizationGrantAdministrationSummary>> GetAuthorizationGrantAsync(AccountSecurityActorContext actor, AuthorizationGrantAdministrationLookupRequest request, CancellationToken cancellationToken = default);
}
