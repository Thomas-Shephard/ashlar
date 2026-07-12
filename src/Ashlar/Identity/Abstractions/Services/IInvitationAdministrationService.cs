namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Provides administrator invitation revocation operations.
/// </summary>
/// <remarks>
/// These operations are intended for administrative and operations tooling and do not authorize the caller.
/// Host applications must protect usage of this service with appropriate admin authorization and step-up policy.
/// Requests require an explicit tenant scope or an intentional all-tenant scope, and raw invitation tokens and token hashes are never returned.
/// Use <see cref="IInvitationAdministrationReader" /> for search and lookup.
/// </remarks>
public interface IInvitationAdministrationService
{
    /// <summary>
    /// Revokes a pending invitation by identifier.
    /// </summary>
    /// <param name="request">Explicit tenant scope, invitation identifier, required audit metadata, and optional reason for the mutating operation.</param>
    /// <param name="cancellationToken">A token that can cancel the revocation.</param>
    /// <returns>Stable revocation status without raw token or token hash data.</returns>
    Task<Result<RevokeInvitationAdministrationResult>> RevokeInvitationAsync(RevokeInvitationAdministrationRequest request, CancellationToken cancellationToken = default);
}
