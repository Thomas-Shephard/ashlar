
namespace Ashlar.Identity.Models.Authentication;

/// <summary>
/// Represents the ashlar user data model.
/// </summary>
public sealed record AshlarUser : ITenantUser
{
    /// <summary>
    /// Gets or sets the id value.
    /// </summary>
    public required Guid Id { get; init; }
    /// <summary>
    /// Gets or sets the email value.
    /// </summary>
    public required string Email { get; init; }
    /// <summary>
    /// Gets or sets the name value.
    /// </summary>
    public string? Name { get; init; }
    /// <summary>
    /// Gets or sets the is active value.
    /// </summary>
    public bool IsActive { get; init; }
    /// <summary>
    /// Gets or sets the tenant id value.
    /// </summary>
    public Guid? TenantId { get; init; }
    /// <summary>
    /// Gets or sets the email verified at value.
    /// </summary>
    public DateTimeOffset? EmailVerifiedAt { get; init; }
}
