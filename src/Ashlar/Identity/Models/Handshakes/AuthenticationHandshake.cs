namespace Ashlar.Identity.Models.Handshakes;

/// <summary>
/// Tracks a short-lived authentication handshake until required factors are verified.
/// </summary>
/// <param name="Id">Stable identifier for the handshake record.</param>
/// <param name="UserId">User associated with the in-progress authentication attempt.</param>
/// <param name="TokenHash">Storage-safe hash of the raw handshake token; the raw token is not exposed after creation.</param>
/// <param name="CreatedAt">UTC time when the handshake was created.</param>
/// <param name="ExpiresAt">UTC time after which the handshake can no longer be verified.</param>
/// <param name="IsRevoked">Whether the handshake has been invalidated before completion.</param>
/// <param name="IsCompleted">Whether all required factors have been verified.</param>
/// <param name="RequiredFactors">Factor types that must be verified before completion.</param>
/// <param name="VerifiedFactors">Factor types already verified for this handshake.</param>
/// <param name="Metadata">Optional host-defined metadata. Do not store secrets or credential material.</param>
/// <param name="RevokedAt">UTC time when the handshake was revoked, when available.</param>
/// <param name="CompletedAt">UTC time when the handshake completed, when available.</param>
public sealed record AuthenticationHandshake(
    Guid Id,
    Guid UserId,
    string TokenHash,
    DateTimeOffset CreatedAt,
    DateTimeOffset ExpiresAt,
    bool IsRevoked,
    bool IsCompleted,
    IReadOnlySet<string> RequiredFactors,
    IReadOnlySet<string> VerifiedFactors,
    IDictionary<string, string>? Metadata = null,
    DateTimeOffset? RevokedAt = null,
    DateTimeOffset? CompletedAt = null);
