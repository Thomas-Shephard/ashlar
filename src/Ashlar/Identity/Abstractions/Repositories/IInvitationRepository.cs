namespace Ashlar.Identity.Abstractions.Repositories;

/// <summary>
/// Stores invitations and supports token-hash lookup for invitation acceptance.
/// </summary>
public interface IInvitationRepository
{
    /// <summary>
    /// Stores a newly issued invitation.
    /// </summary>
    /// <param name="invitation">Invitation to persist. It contains a token hash, not the raw invitation token.</param>
    /// <param name="cancellationToken">A token that can cancel persistence.</param>
    /// <returns>A task that completes when the invitation has been stored.</returns>
    Task CreateInvitationAsync(UserInvitation invitation, CancellationToken cancellationToken = default);
    /// <summary>
    /// Finds an invitation by its storage-safe token hash.
    /// </summary>
    /// <param name="tokenHash">Storage-safe hash of the raw invitation token presented by a caller.</param>
    /// <param name="cancellationToken">A token that can cancel lookup.</param>
    /// <returns>The matching invitation, or <see langword="null" /> when no invitation exists.</returns>
    Task<UserInvitation?> GetInvitationByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default);
    /// <summary>
    /// Updates invitation state after acceptance or revocation.
    /// </summary>
    /// <param name="invitation">Updated invitation to persist.</param>
    /// <param name="expectedVersion">Version expected by optimistic concurrency checks.</param>
    /// <param name="cancellationToken">A token that can cancel the update.</param>
    /// <returns><see langword="true" /> when the invitation was updated.</returns>
    Task<bool> UpdateInvitationAsync(UserInvitation invitation, string expectedVersion, CancellationToken cancellationToken = default);
    /// <summary>
    /// Revokes outstanding invitations for an email address.
    /// </summary>
    /// <param name="email">Normalized email address whose invitations should be revoked.</param>
    /// <param name="tenantId">Tenant scope to revoke within, or <see langword="null" /> for unrestricted revocation across all tenant scopes.</param>
    /// <param name="cancellationToken">A token that can cancel revocation.</param>
    /// <returns>The number of invitations newly revoked.</returns>
    Task<int> RevokeInvitationsByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default);
}
