using Ashlar.Identity.Abstractions;

namespace Ashlar.Identity.Models;

public sealed record AshlarUser : ITenantUser
{
    public required Guid Id { get; init; }
    public required string Email { get; init; }
    public string? Name { get; init; }
    public bool IsActive { get; init; }
    public Guid? TenantId { get; init; }
    public DateTimeOffset? EmailVerifiedAt { get; init; }
}
