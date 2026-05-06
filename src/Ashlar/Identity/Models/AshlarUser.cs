using Ashlar.Identity.Abstractions;

namespace Ashlar.Identity.Models;

public sealed class AshlarUser : ITenantUser
{
    public required Guid Id { get; init; }
    public required string Email { get; init; }
    public string? Name { get; set; }
    public bool IsActive { get; set; }
    public Guid? TenantId { get; init; }
}
