namespace Ashlar.Identity.Models.Passkeys;

/// <summary>
/// Stores a passkey ceremony challenge until registration, authentication, or MFA verification completes.
/// </summary>
public sealed class PasskeyChallenge
{
    /// <summary>
    /// Public challenge identifier used to complete or consume the ceremony.
    /// </summary>
    public required Guid Id { get; init; }
    /// <summary>
    /// Storage format version for serialized challenge data.
    /// </summary>
    public required string Version { get; set; }
    /// <summary>
    /// Passkey ceremony purpose, such as registration, authentication, or MFA verification.
    /// </summary>
    public required string Purpose { get; init; }
    /// <summary>
    /// User associated with the ceremony, when the flow is user-bound.
    /// </summary>
    public Guid? UserId { get; init; }
    /// <summary>
    /// Tenant security boundary for the challenged user, or <see langword="null" /> when the challenge belongs to a global user.
    /// </summary>
    public Guid? TenantId { get; init; }
    /// <summary>
    /// Storage-safe hash of the raw handshake token for MFA passkey verification, when applicable.
    /// </summary>
    public string? HandshakeTokenHash { get; init; }
    /// <summary>
    /// Additional-verification factor family for MFA passkey ceremonies, when applicable.
    /// </summary>
    public string? FactorType { get; init; }
    /// <summary>
    /// User-facing passkey label captured when registration starts.
    /// </summary>
    public string? DisplayName { get; init; }
    /// <summary>
    /// Short-lived WebAuthn challenge sent to the client. It is not a bearer secret, but avoid logging it as routine metadata.
    /// </summary>
    public required string Challenge { get; init; }
    /// <summary>
    /// Short-lived serialized WebAuthn options sent to the client. Store only until the ceremony is consumed or expires.
    /// </summary>
    public required string OptionsJson { get; init; }
    /// <summary>
    /// Relying party identifier expected during verification.
    /// </summary>
    public required string RelyingPartyId { get; init; }
    /// <summary>
    /// Browser origin expected during verification.
    /// </summary>
    public required string Origin { get; init; }
    /// <summary>
    /// UTC time when the ceremony challenge was issued.
    /// </summary>
    public required DateTimeOffset CreatedAt { get; init; }
    /// <summary>
    /// UTC time after which verification must reject the challenge.
    /// </summary>
    public required DateTimeOffset ExpiresAt { get; init; }
    /// <summary>
    /// UTC time when the challenge was successfully consumed, when applicable.
    /// </summary>
    public DateTimeOffset? ConsumedAt { get; set; }
}
