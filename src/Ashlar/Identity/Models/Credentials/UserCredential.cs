namespace Ashlar.Identity.Models.Credentials;

/// <summary>
/// Represents a stored authentication credential for one user and provider.
/// </summary>
public sealed class UserCredential
{
    /// <summary>
    /// Unique identifier for this credential.
    /// </summary>
    public required Guid Id { get; init; }
    /// <summary>
    /// User that owns this credential.
    /// </summary>
    public required Guid UserId { get; init; }
    /// <summary>
    /// Provider family that owns this credential.
    /// </summary>
    public required ProviderType ProviderType { get; init; }
    /// <summary>
    /// Provider name within <see cref="ProviderType" />.
    /// </summary>
    public required string ProviderName { get; init; }

    /// <summary>
    /// A flexible, high-capacity string field to hold SAML NameIDs, OAuth Subjects, or other complex identifiers.
    /// </summary>
    public required string ProviderKey { get; init; }

    /// <summary>
    /// Storage-neutral optimistic concurrency token for conditional credential updates and consumption.
    /// Repository implementations should change this value whenever the credential row changes.
    /// </summary>
    public required string Version { get; set; }

    /// <summary>
    /// Indicates whether the credential is active, not revoked, and has not yet expired.
    /// </summary>
    /// <param name="now">UTC time used for expiry evaluation.</param>
    /// <returns><see langword="true" /> when the credential is active, unrevoked, and unexpired.</returns>
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
    /// <returns>A detached credential copy with the same persisted values.</returns>
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
    /// UTC time when the credential was created.
    /// </summary>
    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>
    /// The most recent time this credential was updated by authentication lifecycle processing.
    /// </summary>
    public DateTimeOffset? UpdatedAt { get; set; }

    /// <summary>
    /// UTC time after which the credential is unavailable.
    /// </summary>
    public DateTimeOffset? ExpiresAt { get; set; }

    /// <summary>
    /// UTC time when the credential was revoked, when applicable.
    /// </summary>
    public DateTimeOffset? RevokedAt { get; set; }

    /// <summary>
    /// Current credential lifecycle status.
    /// </summary>
    public required CredentialStatus Status { get; set; }

    /// <summary>
    /// Provider-neutral credential purpose, such as primary, mfa, recovery, email-login, or password-reset.
    /// </summary>
    public string? Purpose { get; set; }

    /// <summary>
    /// Stores the provider credential payload. Values can include password hashes or protected provider secrets;
    /// do not store raw tokens, plaintext passwords, or unprotected credentials.
    /// </summary>
    public string? CredentialValue { get; set; }

    /// <summary>
    /// The last time this credential was successfully used for authentication.
    /// </summary>
    public DateTimeOffset? LastUsedAt { get; set; }

    /// <summary>
    /// Provider-specific non-secret metadata stored as a JSON blob, such as device AAGUID, backup state,
    /// or FIDO2 signature counters.
    /// Do not include secrets, raw tokens, hashes, credentials, or protected payloads.
    /// Providers should use <c>System.Text.Json</c> for consistent serialization and deserialization of this field.
    /// </summary>
    public string? Metadata { get; set; }
}
