namespace Ashlar.Identity.Models.Invitations;

/// <summary>
/// Provides user invitation behavior.
/// </summary>
public sealed class UserInvitation
{
    /// <summary>
    /// Gets or sets the id value.
    /// </summary>
    public required Guid Id { get; init; }
    /// <summary>
    /// Gets or sets the email value.
    /// </summary>
    public required string Email { get; init; }
    /// <summary>
    /// Gets or sets the tenant id value.
    /// </summary>
    public Guid? TenantId { get; init; }
    /// <summary>
    /// Gets or sets the token hash value.
    /// </summary>
    public required string TokenHash { get; init; }
    /// <summary>
    /// Gets or sets the created at value.
    /// </summary>
    public required DateTimeOffset CreatedAt { get; init; }
    /// <summary>
    /// Gets or sets the updated at value.
    /// </summary>
    public DateTimeOffset? UpdatedAt { get; set; }
    /// <summary>
    /// Gets or sets the expires at value.
    /// </summary>
    public required DateTimeOffset ExpiresAt { get; init; }
    /// <summary>
    /// Gets or sets the accepted at value.
    /// </summary>
    public DateTimeOffset? AcceptedAt { get; set; }
    /// <summary>
    /// Gets or sets the revoked at value.
    /// </summary>
    public DateTimeOffset? RevokedAt { get; set; }
    /// <summary>
    /// Gets or sets the metadata value.
    /// </summary>
    public string? Metadata { get; set; }

    /// <summary>
    /// Storage-neutral optimistic concurrency token for conditional invitation updates and consumption.
    /// Repository implementations should change this value whenever the invitation row changes.
    /// </summary>
    public required string Version { get; set; }

    /// <summary>
    /// Performs the is available operation and returns the result.
    /// </summary>
    /// <param name="now">The now value.</param>
    /// <returns>The operation result.</returns>
    public bool IsAvailable(DateTimeOffset now)
    {
        return AcceptedAt == null && RevokedAt == null && ExpiresAt > now;
    }
}
