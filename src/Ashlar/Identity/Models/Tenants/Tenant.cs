namespace Ashlar.Identity.Models.Tenants;

/// <summary>
/// Represents a tenant that can scope users, credentials, and authorization grants.
/// </summary>
public sealed class Tenant
{
    /// <summary>
    /// Stable tenant identifier.
    /// </summary>
    public required Guid Id { get; init; }
    /// <summary>
    /// Display name for administrator and user-facing tenant selection.
    /// </summary>
    public required string Name { get; set; }
    /// <summary>
    /// Host-defined unique tenant identifier.
    /// </summary>
    public required string Identifier { get; set; }
    /// <summary>
    /// Whether the tenant can participate in authentication flows.
    /// </summary>
    public bool IsActive { get; set; } = true;
}
