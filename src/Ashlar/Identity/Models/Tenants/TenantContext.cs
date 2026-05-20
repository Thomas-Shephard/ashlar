namespace Ashlar.Identity.Models.Tenants;

/// <summary>
/// Describes the tenant scope for operations that support tenant isolation.
/// </summary>
/// <param name="TenantId">The tenant id, or <see langword="null" /> for global scope.</param>
public sealed record TenantContext(Guid? TenantId = null)
{
    /// <summary>
    /// Gets the global tenant scope.
    /// </summary>
    public static TenantContext Global { get; } = new();
}





