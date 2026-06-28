namespace Ashlar.Identity.Models.Authentication;

/// <summary>
/// Represents a user account known to Ashlar.
/// </summary>
public sealed record AshlarUser : ITenantUser
{
    /// <summary>
    /// Stable user identifier.
    /// </summary>
    public required Guid Id { get; init; }
    /// <summary>
    /// Sanitized display/delivery email address. Ashlar derives a separate normalized lookup form for uniqueness, lookup, rate-limit keys, and comparisons.
    /// </summary>
    public required string DisplayEmail { get; init; }
    /// <summary>
    /// Optional display name supplied by the host application.
    /// </summary>
    public string? Name { get; init; }
    /// <summary>
    /// Account state that controls whether authentication can continue.
    /// </summary>
    public UserAccountState AccountState { get; init; } = UserAccountState.Active;
    /// <summary>
    /// Tenant scope for the user, or <see langword="null" /> for a global account.
    /// </summary>
    public Guid? TenantId { get; init; }
    /// <summary>
    /// UTC time when the email address was verified, when known.
    /// </summary>
    public DateTimeOffset? EmailVerifiedAt { get; init; }
}
