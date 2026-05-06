namespace Ashlar.Identity.Models;

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
    IDictionary<string, string>? Metadata = null);
