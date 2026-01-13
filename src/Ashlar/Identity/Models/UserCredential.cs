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
    /// </summary>
    public string? Metadata { get; set; }
}
