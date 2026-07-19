namespace Ashlar.Identity.Models.Invitations;

/// <summary>
/// Successful invitation acceptance result.
/// </summary>
/// <param name="UserId">The user created by the invitation, or the existing active user that accepted it.</param>
/// <param name="AuthenticationResult">Ashlar-issued authentication completion result required before creating a session for the invited user.</param>
public sealed record InvitationAcceptanceResult(Guid UserId, MfaAuthenticationResult AuthenticationResult);
