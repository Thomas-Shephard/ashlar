using Ashlar.Auditing;

namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Creates, accepts, and revokes user invitations.
/// </summary>
public interface IInvitationService
{
    /// <summary>
    /// Creates an invitation and sends the recipient an acceptance link.
    /// </summary>
    /// <param name="request">The invitation details.</param>
    /// <param name="callbackBaseUri">The callback URI that receives the invitation token as a query parameter.</param>
    /// <param name="context">Optional request context for auditing and notifications.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>A result describing whether the invitation was created.</returns>
    Task<Result> CreateInvitationAsync(CreateInvitationRequest request, Uri callbackBaseUri, AuthenticationContext? context = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Accepts an invitation token and creates the invited user.
    /// </summary>
    /// <param name="request">The invitation acceptance details.</param>
    /// <param name="context">Optional request context for auditing and notifications.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The created user ID when the invitation is accepted.</returns>
    Task<Result<Guid>> AcceptInvitationAsync(AcceptInvitationRequest request, AuthenticationContext? context = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes pending invitations for an email address and optional tenant.
    /// </summary>
    /// <param name="email">The invited email address.</param>
    /// <param name="tenantId">The tenant to revoke invitations for, or <see langword="null" /> for global invitations.</param>
    /// <param name="audit">Optional audit metadata describing who requested revocation.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>A result describing whether pending invitations were revoked.</returns>
    Task<Result> RevokeInvitationsAsync(string email, Guid? tenantId = null, AuditContext? audit = null, CancellationToken cancellationToken = default);
}
