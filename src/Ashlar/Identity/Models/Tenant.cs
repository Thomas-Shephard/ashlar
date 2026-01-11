namespace Ashlar.Identity.Models;

public sealed class Tenant
{
    public required Guid Id { get; init; }
    public required string Name { get; set; }
    public required string Identifier { get; set; } // e.g., "acme-corp"
    public bool IsActive { get; set; } = true;
}
