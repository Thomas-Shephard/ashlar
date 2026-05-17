namespace Ashlar.Identity.Models.Passkeys;

/// <summary>
/// Stores a passkey ceremony challenge.
/// </summary>
public sealed class PasskeyChallenge
{
    /// <summary>
    /// Gets or sets the id value.
    /// </summary>
    public required Guid Id { get; init; }
    /// <summary>
    /// Gets or sets the version value.
    /// </summary>
    public required string Version { get; set; }
    /// <summary>
    /// Gets or sets the purpose value.
    /// </summary>
    public required string Purpose { get; init; }
    /// <summary>
    /// Gets or sets the user id value.
    /// </summary>
    public Guid? UserId { get; init; }
    /// <summary>
    /// Gets or sets the handshake token hash value.
    /// </summary>
    public string? HandshakeTokenHash { get; init; }
    /// <summary>
    /// Gets or sets the factor type value.
    /// </summary>
    public string? FactorType { get; init; }
    /// <summary>
    /// Gets or sets the passkey display name captured when registration starts.
    /// </summary>
    public string? DisplayName { get; init; }
    /// <summary>
    /// Gets or sets the challenge value.
    /// </summary>
    public required string Challenge { get; init; }
    /// <summary>
    /// Gets or sets the options json value.
    /// </summary>
    public required string OptionsJson { get; init; }
    /// <summary>
    /// Gets or sets the relying party id value.
    /// </summary>
    public required string RelyingPartyId { get; init; }
    /// <summary>
    /// Gets or sets the origin value.
    /// </summary>
    public required string Origin { get; init; }
    /// <summary>
    /// Gets or sets the created at value.
    /// </summary>
    public required DateTimeOffset CreatedAt { get; init; }
    /// <summary>
    /// Gets or sets the expires at value.
    /// </summary>
    public required DateTimeOffset ExpiresAt { get; init; }
    /// <summary>
    /// Gets or sets the consumed at value.
    /// </summary>
    public DateTimeOffset? ConsumedAt { get; set; }
}
