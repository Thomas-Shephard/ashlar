namespace Ashlar.Identity.Models.Handshakes;

/// <summary>
/// Public details returned when an authentication handshake is created.
/// </summary>
/// <param name="Id">Stable identifier for the handshake record.</param>
/// <param name="UserId">User associated with the in-progress authentication attempt.</param>
/// <param name="TenantId">Tenant security boundary for this handshake, or <see langword="null" /> for a global user.</param>
/// <param name="CreatedAt">UTC time when the handshake was created.</param>
/// <param name="ExpiresAt">UTC time after which the handshake can no longer be verified.</param>
/// <param name="RequiredFactors">Factor types that must be verified before completion.</param>
/// <param name="Metadata">Optional host-defined metadata. Do not store secrets or credential material.</param>
public sealed record CreatedAuthenticationHandshake(
    Guid Id,
    Guid UserId,
    Guid? TenantId,
    DateTimeOffset CreatedAt,
    DateTimeOffset ExpiresAt,
    IReadOnlySet<string> RequiredFactors,
    IDictionary<string, string>? Metadata = null);
