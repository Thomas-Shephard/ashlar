namespace Ashlar.Identity.Models;

public sealed class UserInvitation
{
    public required Guid Id { get; init; }
    public required string Email { get; init; }
    public Guid? TenantId { get; init; }
    public required string TokenHash { get; init; }
    public required DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset? UpdatedAt { get; set; }
    public required DateTimeOffset ExpiresAt { get; init; }
    public DateTimeOffset? AcceptedAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public string? Metadata { get; set; }

    /// <summary>
    /// Storage-neutral optimistic concurrency token for conditional invitation updates and consumption.
    /// Repository implementations should change this value whenever the invitation row changes.
    /// </summary>
    public required string Version { get; set; }

    public bool IsAvailable(DateTimeOffset now)
    {
        return AcceptedAt == null && RevokedAt == null && ExpiresAt > now;
    }
}
