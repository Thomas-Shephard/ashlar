namespace Ashlar.Postgres.Models;

/// <summary>
/// Provides ashlar postgres user behavior.
/// </summary>
public sealed class AshlarPostgresUser : ITenantUser, IHasAuditMetadata
{
    /// <summary>
    /// Gets or sets the id value.
    /// </summary>
    public required Guid Id { get; init; }
    /// <summary>
    /// Gets or sets the email value.
    /// </summary>
    public required string Email { get; set; }
    /// <summary>
    /// Gets or sets the name value.
    /// </summary>
    public string? Name { get; set; }
    /// <summary>
    /// Gets or sets the is active value.
    /// </summary>
    public bool IsActive { get; set; }
    /// <summary>
    /// Gets or sets the tenant id value.
    /// </summary>
    public Guid? TenantId { get; init; }
    /// <summary>
    /// Gets or sets the email verified at value.
    /// </summary>
    public DateTimeOffset? EmailVerifiedAt { get; set; }
    /// <summary>
    /// Gets or sets the created at value.
    /// </summary>
    public required DateTimeOffset CreatedAt { get; init; }
    /// <summary>
    /// Gets or sets the updated at value.
    /// </summary>
    public DateTimeOffset? UpdatedAt { get; set; }
}
