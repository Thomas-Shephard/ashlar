namespace Ashlar.Postgres.Models;

/// <summary>
/// PostgreSQL-backed user record returned by Ashlar repositories.
/// </summary>
public sealed class AshlarPostgresUser : ITenantUser, IHasAuditMetadata
{
    /// <summary>
    /// Stable user identifier.
    /// </summary>
    public required Guid Id { get; init; }
    /// <summary>
    /// Sanitized display/delivery email address. This is not the normalized lookup form.
    /// </summary>
    public required string DisplayEmail { get; set; }
    /// <summary>
    /// Optional display name supplied by the host application.
    /// </summary>
    public string? Name { get; set; }
    /// <summary>
    /// Account state that controls whether authentication can continue.
    /// </summary>
    public UserAccountState AccountState { get; set; } = UserAccountState.Active;
    /// <summary>
    /// Tenant scope for the user, or <see langword="null" /> for a global account.
    /// </summary>
    public Guid? TenantId { get; init; }
    /// <summary>
    /// UTC time when the email address was verified, when known.
    /// </summary>
    public DateTimeOffset? EmailVerifiedAt { get; set; }
    /// <summary>
    /// UTC time when the account was created.
    /// </summary>
    public required DateTimeOffset CreatedAt { get; init; }
    /// <summary>
    /// UTC time when account metadata or state last changed, when known.
    /// </summary>
    public DateTimeOffset? UpdatedAt { get; set; }
}
