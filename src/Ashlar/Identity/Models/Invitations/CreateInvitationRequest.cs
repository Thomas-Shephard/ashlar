namespace Ashlar.Identity.Models.Invitations;

/// <summary>
/// Request to create an invitation and send an acceptance link.
/// </summary>
public sealed class CreateInvitationRequest
{
    /// <summary>
    /// Email address that will receive the invitation. Treat as personal data.
    /// </summary>
    public required string Email { get; init; }
    /// <summary>
    /// Tenant the invitation applies to, or <see langword="null" /> for a global invitation.
    /// </summary>
    public Guid? TenantId { get; init; }
    /// <summary>
    /// Optional lifetime for the invitation token.
    /// </summary>
    public TimeSpan? Expiry { get; init; }
    /// <summary>
    /// Provider-neutral invitation metadata. Do not include secrets or raw tokens.
    /// </summary>
    public string? Metadata { get; init; }
}
