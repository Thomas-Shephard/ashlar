namespace Ashlar.Identity.Models;

public sealed class AuthenticationSession
{
    public required Guid Id { get; init; }
    public required Guid UserId { get; init; }
    public required string TokenHash { get; init; }
    public required DateTimeOffset CreatedAt { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }
    public DateTimeOffset? LastSeenAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public string? RevocationReason { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public string? Metadata { get; set; }

    public bool IsActive(DateTimeOffset now)
    {
        return RevokedAt == null && ExpiresAt > now;
    }
}
