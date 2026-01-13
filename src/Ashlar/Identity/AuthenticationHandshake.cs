using Ashlar.Identity.Abstractions;

namespace Ashlar.Identity;

public sealed record AuthenticationHandshake(
    string SessionTicket,
    Guid UserId,
    IReadOnlyList<string> VerifiedFactors,
    Guid? TenantId = null) : IAuthenticationHandshake;
