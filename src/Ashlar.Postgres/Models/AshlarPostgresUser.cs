using Ashlar.Identity.Abstractions;

namespace Ashlar.Postgres.Models;

public sealed class AshlarPostgresUser : ITenantUser, IHasAuditMetadata
{
    public required Guid Id { get; init; }
    public required string Email { get; set; }
    public string? Name { get; set; }
    public bool IsActive { get; set; }
    public Guid? TenantId { get; init; }
    public DateTimeOffset? EmailVerifiedAt { get; set; }
    public required DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset? UpdatedAt { get; set; }
}
