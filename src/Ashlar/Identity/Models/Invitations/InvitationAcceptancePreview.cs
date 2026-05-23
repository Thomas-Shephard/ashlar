namespace Ashlar.Identity.Models.Invitations;

/// <summary>
/// Describes a currently acceptable invitation without consuming it.
/// </summary>
/// <param name="Email">The invited email address.</param>
/// <param name="TenantId">The invitation tenant scope.</param>
public sealed record InvitationAcceptancePreview(string Email, Guid? TenantId);
