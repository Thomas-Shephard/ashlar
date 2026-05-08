namespace Ashlar.Authorization.Models;

public sealed class AuthorizationGrant
{
    public required Guid Id { get; init; }
    public required Guid UserId { get; init; }
    public Guid? TenantId { get; init; }
    public string? ScopeType { get; init; }
    public string? ScopeId { get; init; }
    public string? Role { get; init; }
    public string? Permission { get; init; }
    public required DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset? ExpiresAt { get; init; }
    public DateTimeOffset? RevokedAt { get; set; }
    public string? Metadata { get; init; }

    public bool IsActive(DateTimeOffset now)
    {
        if (RevokedAt != null)
        {
            return false;
        }

        if (ExpiresAt == null)
        {
            return true;
        }

        return ExpiresAt.Value > now;
    }
}
