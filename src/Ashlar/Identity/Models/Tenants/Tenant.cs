namespace Ashlar.Identity.Models.Tenants;

/// <summary>
/// Provides tenant behavior.
/// </summary>
public sealed class Tenant
{
    /// <summary>
    /// Gets or sets the id value.
    /// </summary>
    public required Guid Id { get; init; }
    /// <summary>
    /// Gets or sets the name value.
    /// </summary>
    public required string Name { get; set; }
    /// <summary>
    /// Gets or sets the identifier value.
    /// </summary>
    public required string Identifier { get; set; } // e.g., "acme-corp"
    /// <summary>
    /// Gets or sets the is active value.
    /// </summary>
    public bool IsActive { get; set; } = true;
}





