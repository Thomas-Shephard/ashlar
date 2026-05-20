namespace Ashlar.Identity.Models.Sessions;

/// <summary>
/// Provides authentication session behavior.
/// </summary>
public sealed class AuthenticationSession
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
    /// Gets or sets the token hash value.
    /// </summary>
    public required string TokenHash { get; init; }
    /// <summary>
    /// Gets or sets the created at value.
    /// </summary>
    public required DateTimeOffset CreatedAt { get; init; }
    /// <summary>
    /// Gets or sets when the user authenticated for this session.
    /// </summary>
    public DateTimeOffset? AuthenticatedAt { get; set; }
    /// <summary>
    /// Gets or sets the primary provider used to create this session.
    /// </summary>
    public AuthenticationProviderKey? PrimaryProvider { get; set; }
    /// <summary>
    /// Gets or sets when additional verification was completed for this session.
    /// </summary>
    public DateTimeOffset? AdditionalVerificationAt { get; set; }
    /// <summary>
    /// Gets or sets the provider used for additional verification.
    /// </summary>
    public AuthenticationProviderKey? AdditionalVerificationProvider { get; set; }
    /// <summary>
    /// Gets or sets the verified factor family used for additional verification.
    /// </summary>
    public string? AdditionalVerificationFactor { get; set; }
    /// <summary>
    /// Gets or sets the expires at value.
    /// </summary>
    public required DateTimeOffset ExpiresAt { get; init; }
    /// <summary>
    /// Gets or sets the last seen at value.
    /// </summary>
    public DateTimeOffset? LastSeenAt { get; set; }
    /// <summary>
    /// Gets or sets the revoked at value.
    /// </summary>
    public DateTimeOffset? RevokedAt { get; set; }
    /// <summary>
    /// Gets or sets the revocation reason value.
    /// </summary>
    public string? RevocationReason { get; set; }
    /// <summary>
    /// Gets or sets the ip address value.
    /// </summary>
    public string? IpAddress { get; set; }
    /// <summary>
    /// Gets or sets the user agent value.
    /// </summary>
    public string? UserAgent { get; set; }
    /// <summary>
    /// Gets or sets the metadata value.
    /// </summary>
    public string? Metadata { get; set; }

    /// <summary>
    /// Performs the is active operation and returns the result.
    /// </summary>
    /// <param name="now">The now value.</param>
    /// <returns>The operation result.</returns>
    public bool IsActive(DateTimeOffset now)
    {
        return RevokedAt == null && ExpiresAt > now;
    }
}
