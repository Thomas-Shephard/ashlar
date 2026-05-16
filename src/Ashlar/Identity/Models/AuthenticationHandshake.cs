namespace Ashlar.Identity.Models;

/// <summary>
/// Represents the authentication handshake data model.
/// </summary>
/// <param name="Id">The id value.</param>
/// <param name="UserId">The user <paramref name="Id" /> value.</param>
/// <param name="TokenHash">The token hash value.</param>
/// <param name="CreatedAt">The created at value.</param>
/// <param name="ExpiresAt">The expires at value.</param>
/// <param name="IsRevoked">The is revoked value.</param>
/// <param name="IsCompleted">The is completed value.</param>
/// <param name="RequiredFactors">The required factors value.</param>
/// <param name="VerifiedFactors">The verified factors value.</param>
/// <param name="Metadata">The metadata value.</param>
/// <param name="RevokedAt">The revoked at value.</param>
/// <param name="CompletedAt">The completed at value.</param>
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
