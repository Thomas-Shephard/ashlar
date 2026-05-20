namespace Ashlar.Authorization.Models;

/// <summary>
/// Provides authorization grant behavior.
/// </summary>
public sealed class AuthorizationGrant
{
    /// <summary>
    /// Gets or sets the id value.
    /// </summary>
    public required Guid Id { get; init; }
    /// <summary>
    /// Gets or sets the user id value.
    /// </summary>
    public required Guid UserId { get; init; }
    /// <summary>
    /// Gets or sets the tenant id value.
    /// </summary>
    public Guid? TenantId { get; init; }
    /// <summary>
    /// Gets or sets the scope type value.
    /// </summary>
    public string? ScopeType { get; init; }
    /// <summary>
    /// Gets or sets the scope id value.
    /// </summary>
    public string? ScopeId { get; init; }
    /// <summary>
    /// Gets or sets the role value.
    /// </summary>
    public string? Role { get; init; }
    /// <summary>
    /// Gets or sets the permission value.
    /// </summary>
    public string? Permission { get; init; }
    /// <summary>
    /// Gets or sets the created at value.
    /// </summary>
    public required DateTimeOffset CreatedAt { get; init; }
    /// <summary>
    /// Gets or sets the expires at value.
    /// </summary>
    public DateTimeOffset? ExpiresAt { get; init; }
    /// <summary>
    /// Gets or sets the revoked at value.
    /// </summary>
    public DateTimeOffset? RevokedAt { get; set; }
    /// <summary>
    /// Gets or sets the metadata value.
    /// </summary>
    public string? Metadata { get; init; }

    /// <summary>
    /// Performs the is active operation and returns the result.
    /// </summary>
    /// <param name="now">The now value.</param>
    /// <returns>The operation result.</returns>
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


