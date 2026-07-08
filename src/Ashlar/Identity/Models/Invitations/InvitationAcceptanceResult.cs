namespace Ashlar.Identity.Models.Invitations;

/// <summary>
/// Successful invitation acceptance result.
/// </summary>
/// <param name="UserId">The user created or activated by the invitation.</param>
/// <param name="AuthenticationResult">Ashlar-issued authentication completion result required before creating a session for the invited user.</param>
public sealed record InvitationAcceptanceResult(Guid UserId, MfaAuthenticationResult AuthenticationResult);
