using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;

namespace Ashlar.Identity;

public sealed class AuthenticationHandshake : IAuthenticationHandshake
{
    public required Guid UserId { get; init; }
    public required IReadOnlyList<ProviderType> VerifiedFactors { get; init; }
    public Guid? TenantId { get; init; }
    public string? SessionTicket { get; init; }
}
