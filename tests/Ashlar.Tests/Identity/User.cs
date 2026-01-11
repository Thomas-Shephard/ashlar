using Ashlar.Identity.Abstractions;

namespace Ashlar.Tests.Identity;

public sealed class User : ITenantUser
{
    public required Guid Id { get; init; }
    public required string Email { get; set; }
    public string? Name { get; set; }
    public bool IsActive { get; set; } = true;
    public Guid? TenantId { get; set; }
}
