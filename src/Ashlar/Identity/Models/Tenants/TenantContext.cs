namespace Ashlar.Identity.Models.Tenants;

/// <summary>
/// Describes the tenant scope for operations that support tenant isolation.
/// </summary>
/// <param name="TenantId">Tenant boundary for scoped operations, or <see langword="null" /> for global scope.</param>
public sealed record TenantContext(Guid? TenantId = null)
{
    /// <summary>
    /// Tenant scope for global users and operations outside a tenant boundary.
    /// </summary>
    public static TenantContext Global { get; } = new();
}
