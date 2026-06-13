namespace Ashlar.Identity.Models.Invitations;

/// <summary>
/// Request to accept an invitation token.
/// </summary>
public sealed class AcceptInvitationRequest
{
    /// <summary>
    /// Raw invitation token from the acceptance link. Do not log or persist this value.
    /// </summary>
    public required string? Token { get; init; }
    /// <summary>
    /// Optional display name for the user created from the invitation.
    /// </summary>
    public string? UserName { get; init; }
}
