namespace Ashlar.Identity.Models;

public sealed class UserCredential
{
    public required Guid Id { get; init; }
    public required Guid UserId { get; init; }
    public required ProviderType ProviderType { get; init; }
    public required string ProviderName { get; init; }

    /// <summary>
    /// A flexible, high-capacity string field to hold SAML NameIDs, OAuth Subjects, or other complex identifiers.
    /// </summary>
    public required string ProviderKey { get; init; }

    /// <summary>
    /// Storage-neutral optimistic concurrency token for conditional credential updates and consumption.
    /// Repository implementations should change this value whenever the credential row changes.
    /// </summary>
    public required string Version { get; init; }

    /// <summary>
    /// Indicates whether the credential is active, not revoked, and has not yet expired.
    /// </summary>
    /// <param name="now">The reference time to check against, typically UTC now.</param>
    public bool IsAvailable(DateTimeOffset now)
    {
        if (Status != CredentialStatus.Active)
        {
            return false;
        }

        if (RevokedAt != null)
        {
            return false;
        }

        if (ExpiresAt.HasValue && ExpiresAt.Value <= now)
        {
            return false;
        }

        return true;
    }

    /// <summary>
    /// Creates a detached copy of this credential.
    /// </summary>
    public UserCredential Clone()
    {
        return new UserCredential
        {
            Id = Id,
            UserId = UserId,
            ProviderType = ProviderType,
            ProviderName = ProviderName,
            ProviderKey = ProviderKey,
            Version = Version,
            CreatedAt = CreatedAt,
            UpdatedAt = UpdatedAt,
            ExpiresAt = ExpiresAt,
            RevokedAt = RevokedAt,
            Status = Status,
            Purpose = Purpose,
            CredentialValue = CredentialValue,
            LastUsedAt = LastUsedAt,
            Metadata = Metadata
        };
    }

    /// <summary>
    /// The time this credential was created.
    /// </summary>
    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>
    /// The most recent time this credential was updated by authentication lifecycle processing.
    /// </summary>
    public DateTimeOffset? UpdatedAt { get; set; }

    /// <summary>
    /// The time this credential expires. Expiry is derived from this value rather than stored as a status.
    /// </summary>
    public DateTimeOffset? ExpiresAt { get; set; }

    /// <summary>
    /// The time this credential was revoked.
    /// </summary>
    public DateTimeOffset? RevokedAt { get; set; }

    /// <summary>
    /// The lifecycle status for this credential.
    /// </summary>
    public required CredentialStatus Status { get; set; }

    /// <summary>
    /// Provider-neutral credential purpose, such as primary, mfa, recovery, email-login, or password-reset.
    /// </summary>
    public string? Purpose { get; set; }

    /// <summary>
    /// For local passwords, this stores the hashed password. For other providers, it might store refresh tokens or other metadata.
    /// Ensure any sensitive metadata stored here is appropriately protected by the repository layer.
    /// </summary>
    public string? CredentialValue { get; set; }

    /// <summary>
    /// The last time this credential was successfully used for authentication.
    /// </summary>
    public DateTimeOffset? LastUsedAt { get; set; }

    /// <summary>
    /// Provider-specific metadata stored as a JSON blob.
    /// e.g., device AAGUID, backup state, or FIDO2 signature counters.
    /// Providers should use <c>System.Text.Json</c> for consistent serialization and deserialization of this field.
    /// </summary>
    public string? Metadata { get; set; }
}
