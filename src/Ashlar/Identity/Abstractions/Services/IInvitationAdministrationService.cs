namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Provides actor-bound administrator invitation creation and revocation operations.
/// </summary>
/// <remarks>
/// Operations require an active actor session, fresh administration proof, explicit scope, host authorization, and durable audit.
/// Requests require an explicit tenant scope or an intentional all-tenant scope, and raw invitation tokens and token hashes are never returned.
/// Use <see cref="IInvitationAdministrationReader" /> for search and lookup.
/// </remarks>
public interface IInvitationAdministrationService
{
    /// <summary>Fresh MFA proof purpose required to create invitations.</summary>
    public const string CreateProofPurpose = "invitation-create";

    /// <summary>Fresh MFA proof purpose required to revoke invitations.</summary>
    public const string RevokeProofPurpose = "invitation-revoke";

    /// <summary>Creates an invitation in an explicit tenant or global scope.</summary>
    /// <param name="actor">Authenticated administrator context.</param>
    /// <param name="request">Invitation details and explicit scope.</param>
    /// <param name="cancellationToken">A token that can cancel creation.</param>
    /// <returns>A result describing whether the invitation was created.</returns>
    Task<Result> CreateInvitationAsync(AccountSecurityActorContext actor, CreateInvitationAdministrationRequest request, CancellationToken cancellationToken = default);

    /// <summary>Revokes pending invitations created before the operation starts for an email address in an explicit scope.</summary>
    /// <param name="actor">Authenticated administrator context.</param>
    /// <param name="request">Email and explicit revocation scope.</param>
    /// <param name="cancellationToken">A token that can cancel revocation.</param>
    /// <returns>The number of matching invitations revoked.</returns>
    Task<Result<RevokeInvitationsByEmailAdministrationResult>> RevokeInvitationsByEmailAsync(AccountSecurityActorContext actor, RevokeInvitationsByEmailAdministrationRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a pending invitation by identifier.
    /// </summary>
    /// <param name="actor">Authenticated administrator context.</param>
    /// <param name="request">Explicit tenant scope, invitation identifier, and optional reason for the mutating operation.</param>
    /// <param name="cancellationToken">A token that can cancel the revocation.</param>
    /// <returns>Stable revocation status without raw token or token hash data.</returns>
    Task<Result<RevokeInvitationByIdAdministrationResult>> RevokeInvitationByIdAsync(AccountSecurityActorContext actor, RevokeInvitationByIdAdministrationRequest request, CancellationToken cancellationToken = default);
}
