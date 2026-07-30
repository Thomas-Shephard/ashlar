namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Provides bearer-token invitation onboarding flows.
/// </summary>
public interface IInvitationService
{
    /// <summary>
    /// Gets safe invitation details needed to validate an acceptance flow before consuming the invitation token.
    /// </summary>
    /// <param name="token">The raw invitation token from the acceptance link. Do not log or persist this value.</param>
    /// <param name="context">Optional request context for tenant scope and auditing. Tenant-owned invitations require a matching tenant context; a missing tenant is global-only.</param>
    /// <param name="cancellationToken">A token that can cancel invitation preview lookup.</param>
    /// <returns>The acceptable invitation details, or an invalid invitation failure.</returns>
    Task<Result<InvitationAcceptancePreview>> GetInvitationAcceptancePreviewAsync(string? token, AuthenticationContext? context = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Accepts an invitation token and creates the invited user.
    /// </summary>
    /// <param name="request">The invitation acceptance details.</param>
    /// <param name="context">Optional request context for tenant scope, auditing, and notifications. Tenant-owned invitations require a matching tenant context; a missing tenant is global-only.</param>
    /// <param name="cancellationToken">A token that can cancel invitation acceptance.</param>
    /// <returns>The accepted user and Ashlar-verified session issuance capability when the invitation is accepted.</returns>
    Task<Result<InvitationAcceptanceResult>> AcceptInvitationAsync(AcceptInvitationRequest request, AuthenticationContext? context = null, CancellationToken cancellationToken = default);
}
