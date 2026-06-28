namespace Ashlar.Sqlite.Models;

/// <summary>
/// SQLite-backed user record returned by Ashlar repositories.
/// </summary>
public sealed class AshlarSqliteUser : ITenantUser, IHasAuditMetadata
{
    public required Guid Id { get; init; }
    /// <summary>
    /// Sanitized display/delivery email address. This is not the normalized lookup form.
    /// </summary>
    public required string DisplayEmail { get; set; }
    public string? Name { get; set; }
    public UserAccountState AccountState { get; set; } = UserAccountState.Active;
    public Guid? TenantId { get; init; }
    public DateTimeOffset? EmailVerifiedAt { get; set; }
    public required DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset? UpdatedAt { get; set; }
}
