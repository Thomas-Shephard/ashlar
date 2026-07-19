namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Provides administrator invitation revocation operations.
/// </summary>
/// <remarks>
/// Operations require an active actor session, fresh administration proof, explicit scope, host authorization, and durable audit.
/// Requests require an explicit tenant scope or an intentional all-tenant scope, and raw invitation tokens and token hashes are never returned.
/// Use <see cref="IInvitationAdministrationReader" /> for search and lookup.
/// </remarks>
public interface IInvitationAdministrationService
{
    /// <summary>
    /// Revokes a pending invitation by identifier.
    /// </summary>
    /// <param name="actor">Authenticated administrator context.</param>
    /// <param name="request">Explicit tenant scope, invitation identifier, required audit metadata, and optional reason for the mutating operation.</param>
    /// <param name="cancellationToken">A token that can cancel the revocation.</param>
    /// <returns>Stable revocation status without raw token or token hash data.</returns>
    Task<Result<RevokeInvitationAdministrationResult>> RevokeInvitationAsync(AccountSecurityActorContext actor, RevokeInvitationAdministrationRequest request, CancellationToken cancellationToken = default);
}
