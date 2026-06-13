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
    /// <param name="cancellationToken">A token that can cancel invitation creation or message delivery.</param>
    /// <returns>A result describing whether the invitation was created.</returns>
    Task<Result> CreateInvitationAsync(CreateInvitationRequest request, Uri callbackBaseUri, AuthenticationContext? context = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets safe invitation details needed to validate an acceptance flow before consuming the invitation token.
    /// </summary>
    /// <param name="token">The raw invitation token from the acceptance link. Do not log or persist this value.</param>
    /// <param name="context">Optional request context for auditing.</param>
    /// <param name="cancellationToken">A token that can cancel invitation preview lookup.</param>
    /// <returns>The acceptable invitation details, or an invalid invitation failure.</returns>
    Task<Result<InvitationAcceptancePreview>> GetInvitationAcceptancePreviewAsync(string? token, AuthenticationContext? context = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Accepts an invitation token and creates the invited user.
    /// </summary>
    /// <param name="request">The invitation acceptance details.</param>
    /// <param name="context">Optional request context for auditing and notifications.</param>
    /// <param name="cancellationToken">A token that can cancel invitation acceptance.</param>
    /// <returns>The created user ID when the invitation is accepted.</returns>
    Task<Result<Guid>> AcceptInvitationAsync(AcceptInvitationRequest request, AuthenticationContext? context = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes pending invitations for an email address and optional tenant.
    /// </summary>
    /// <param name="email">The invited email address.</param>
    /// <param name="tenantId">Tenant scope to revoke within; omit only when intentionally revoking invitations across all tenant scopes for the email address.</param>
    /// <param name="audit">Optional audit metadata describing who requested revocation.</param>
    /// <param name="cancellationToken">A token that can cancel invitation revocation.</param>
    /// <returns>A result describing whether pending invitations were revoked.</returns>
    Task<Result> RevokeInvitationsAsync(string email, Guid? tenantId = null, AuditContext? audit = null, CancellationToken cancellationToken = default);
}
