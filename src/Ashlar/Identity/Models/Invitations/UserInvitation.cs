namespace Ashlar.Identity.Models.Invitations;

/// <summary>
/// Represents a persisted invitation that can create or attach a user to a tenant.
/// </summary>
public sealed class UserInvitation
{
    /// <summary>
    /// Unique identifier for this invitation.
    /// </summary>
    public required Guid Id { get; init; }
    /// <summary>
    /// Sanitized display/delivery email address on the invitation. This is not the normalized lookup form. Treat as personal data.
    /// </summary>
    public required string DisplayEmail { get; init; }
    /// <summary>
    /// Tenant the invite applies to, or <see langword="null" /> for a global invitation.
    /// </summary>
    public Guid? TenantId { get; init; }
    /// <summary>
    /// Hash of the raw invitation token. The raw token is not stored on the invitation.
    /// </summary>
    public required string TokenHash { get; init; }
    /// <summary>
    /// Time the invitation was created.
    /// </summary>
    public required DateTimeOffset CreatedAt { get; init; }
    /// <summary>
    /// Most recent time the invitation was updated.
    /// </summary>
    public DateTimeOffset? UpdatedAt { get; set; }
    /// <summary>
    /// Time after which the invitation can no longer be accepted.
    /// </summary>
    public required DateTimeOffset ExpiresAt { get; init; }
    /// <summary>
    /// Time the invitation was accepted, or <see langword="null" /> while it remains unused.
    /// </summary>
    public DateTimeOffset? AcceptedAt { get; set; }
    /// <summary>
    /// Time the invitation was revoked, or <see langword="null" /> while it remains usable.
    /// </summary>
    public DateTimeOffset? RevokedAt { get; set; }
    /// <summary>
    /// Provider-neutral invitation metadata. Do not store secrets or raw invitation tokens in this value.
    /// </summary>
    public string? Metadata { get; set; }

    /// <summary>
    /// Storage-neutral optimistic concurrency token for conditional invitation updates and consumption.
    /// Repository implementations should change this value whenever the invitation row changes.
    /// </summary>
    public required string Version { get; set; }

    /// <summary>
    /// Determines whether the invitation can currently be accepted.
    /// </summary>
    /// <param name="now">UTC time used for expiry evaluation.</param>
    /// <returns><see langword="true" /> when the invitation is unaccepted, unrevoked, and unexpired.</returns>
    public bool IsAvailable(DateTimeOffset now)
    {
        return AcceptedAt == null && RevokedAt == null && ExpiresAt > now;
    }
}
