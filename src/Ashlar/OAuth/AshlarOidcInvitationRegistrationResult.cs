namespace Ashlar.OAuth;

/// <summary>
/// Describes the result of accepting an Ashlar invitation with a validated OpenID Connect provider.
/// </summary>
/// <param name="Status">The registration outcome.</param>
/// <param name="UserId">The accepted Ashlar user id, when invitation acceptance succeeded.</param>
/// <param name="InvitationAcceptance">The underlying invitation acceptance result, when attempted.</param>
/// <param name="CredentialLink">The underlying credential link result, when attempted.</param>
public sealed record AshlarOidcInvitationRegistrationResult(
    AshlarOidcInvitationRegistrationStatus Status,
    Guid? UserId = null,
    Result<Ashlar.Identity.Models.Invitations.InvitationAcceptanceResult>? InvitationAcceptance = null,
    Result? CredentialLink = null)
{
    /// <summary>
    /// Gets a value indicating whether the invitation was accepted and a new OIDC credential was linked.
    /// </summary>
    public bool Registered => Status == AshlarOidcInvitationRegistrationStatus.Registered;
}

/// <summary>
/// Enumerates safe result states for OIDC invitation registration. Public UI should still prefer generic failure messages.
/// </summary>
public enum AshlarOidcInvitationRegistrationStatus
{
    /// <summary>
    /// The invitation was accepted and the OIDC credential was linked.
    /// </summary>
    Registered,
    /// <summary>
    /// The OIDC credential is already linked to the accepted user.
    /// </summary>
    AlreadyLinked,
    /// <summary>
    /// The requested provider is not configured.
    /// </summary>
    UnsupportedProvider,
    /// <summary>
    /// The external authentication ticket could not be completed.
    /// </summary>
    AuthenticationFailed,
    /// <summary>
    /// The external authentication ticket did not match the requested provider.
    /// </summary>
    ProviderMismatch,
    /// <summary>
    /// The external principal was missing required identity data.
    /// </summary>
    InvalidPrincipal,
    /// <summary>
    /// The invitation token is invalid, expired, revoked, or already consumed.
    /// </summary>
    InvalidInvitation,
    /// <summary>
    /// The verified OIDC email did not match the invitation email.
    /// </summary>
    EmailMismatch,
    /// <summary>
    /// The external identity lacks an acceptable verified or provider-trusted email identity claim.
    /// </summary>
    EmailNotVerified,
    /// <summary>
    /// The OIDC credential is already linked to a different Ashlar user.
    /// </summary>
    AlreadyLinkedToAnotherUser,
    /// <summary>
    /// Invitation acceptance succeeded, but credential linking failed.
    /// </summary>
    LinkFailed,
    /// <summary>
    /// Invitation registration was blocked by a rate limiter.
    /// </summary>
    RateLimited,
    /// <summary>
    /// Registration failed for another Ashlar service reason.
    /// </summary>
    Failed
}
