
namespace Ashlar.Sqlite.Models;

/// <summary>
/// Provides Ashlar SQLite user behavior.
/// </summary>
public sealed class AshlarSqliteUser : ITenantUser, IHasAuditMetadata
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
