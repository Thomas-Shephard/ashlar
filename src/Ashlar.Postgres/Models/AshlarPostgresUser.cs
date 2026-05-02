using Ashlar.Identity.Abstractions;

namespace Ashlar.Postgres.Models;

public sealed class AshlarPostgresUser : ITenantUser, IHasAuditMetadata
{
    public required Guid Id { get; init; }
    public required string Email { get; init; }
    public string? Name { get; init; }
    public bool IsActive { get; init; }
    public Guid? TenantId { get; init; }
    public required DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset? UpdatedAt { get; set; }
}
