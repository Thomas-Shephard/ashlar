namespace Ashlar.Authorization.Models;

/// <summary>
/// Describes a role or permission grant assigned to a user within an optional tenant and resource scope.
/// </summary>
public sealed class AuthorizationGrant
{
    /// <summary>
    /// Unique identifier for this grant.
    /// </summary>
    public required Guid Id { get; init; }
    /// <summary>
    /// User that receives the role or permission.
    /// </summary>
    public required Guid UserId { get; init; }
    /// <summary>
    /// Tenant that bounds the grant. A <see langword="null" /> value represents global scope.
    /// </summary>
    public Guid? TenantId { get; init; }
    /// <summary>
    /// Optional resource type that further constrains where the grant applies.
    /// </summary>
    public string? ScopeType { get; init; }
    /// <summary>
    /// Optional resource identifier within <see cref="ScopeType" />.
    /// </summary>
    public string? ScopeId { get; init; }
    /// <summary>
    /// Role assigned by this grant. A grant should use either a role or a permission, not both.
    /// </summary>
    public string? Role { get; init; }
    /// <summary>
    /// Permission assigned by this grant. A grant should use either a permission or a role, not both.
    /// </summary>
    public string? Permission { get; init; }
    /// <summary>
    /// Time the grant was created.
    /// </summary>
    public required DateTimeOffset CreatedAt { get; init; }
    /// <summary>
    /// Optional time after which the grant no longer applies.
    /// </summary>
    public DateTimeOffset? ExpiresAt { get; init; }
    /// <summary>
    /// Time the grant was revoked, or <see langword="null" /> while it remains usable.
    /// </summary>
    public DateTimeOffset? RevokedAt { get; set; }
    /// <summary>
    /// Provider-neutral metadata for administrative display. Do not store secrets or credentials in this value.
    /// </summary>
    public string? Metadata { get; init; }

    /// <summary>
    /// Determines whether the grant is currently usable.
    /// </summary>
    /// <param name="now">UTC time used for expiry evaluation.</param>
    /// <returns><see langword="true" /> when the grant is not revoked and has not expired.</returns>
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
