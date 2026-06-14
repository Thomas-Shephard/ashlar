namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Provides administrator invitation search, detail, and revocation operations.
/// </summary>
/// <remarks>
/// These operations are intended for administrative and operations tooling and do not authorize the caller.
/// Host applications must protect usage of this service with appropriate admin authorization and step-up policy.
/// Requests require an explicit tenant scope or an intentional all-tenant scope, and raw invitation tokens and token hashes are never returned.
/// </remarks>
public interface IInvitationAdministrationService
{
    /// <summary>
    /// Searches invitations for administrator and operations interfaces.
    /// </summary>
    /// <param name="request">Explicit tenant scope, filters, and paging options for the read-only search.</param>
    /// <param name="cancellationToken">A token that can cancel the search.</param>
    /// <returns>Provider-neutral invitation summaries that do not include raw tokens or token hashes.</returns>
    Task<Result<InvitationSearchResult>> SearchInvitationsAsync(SearchInvitationsRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets display-safe invitation detail by identifier.
    /// </summary>
    /// <param name="request">Explicit tenant scope and invitation identifier for the read-only lookup.</param>
    /// <param name="cancellationToken">A token that can cancel the lookup.</param>
    /// <returns>Invitation detail without raw token, token hash, or provider version metadata.</returns>
    Task<Result<InvitationAdministrationDetail>> GetInvitationAsync(InvitationAdministrationDetailRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a pending invitation by identifier.
    /// </summary>
    /// <param name="request">Explicit tenant scope, invitation identifier, required audit metadata, and optional reason for the mutating operation.</param>
    /// <param name="cancellationToken">A token that can cancel the revocation.</param>
    /// <returns>Stable revocation status without raw token or token hash data.</returns>
    Task<Result<RevokeInvitationAdministrationResult>> RevokeInvitationAsync(RevokeInvitationAdministrationRequest request, CancellationToken cancellationToken = default);
}
