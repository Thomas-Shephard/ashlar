namespace Ashlar.Identity.Models.Invitations;

/// <summary>
/// Describes a currently acceptable invitation without consuming it.
/// </summary>
/// <param name="DisplayEmail">The sanitized display/delivery email address on the invitation. This is not the normalized lookup form.</param>
/// <param name="TenantId">Tenant scope that owns the invitation, when tenant-scoped.</param>
public sealed record InvitationAcceptancePreview(string DisplayEmail, Guid? TenantId);
