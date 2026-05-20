namespace Ashlar.Identity.Models.Bootstrap;

/// <summary>
/// Provides bootstrap options behavior.
/// </summary>
public sealed class BootstrapOptions
{
    /// <summary>
    /// Gets or sets the grants value.
    /// </summary>
    public List<BootstrapGrantTemplate> Grants { get; set; } = [];
}

/// <summary>
/// Provides bootstrap grant template behavior.
/// </summary>
public sealed class BootstrapGrantTemplate
{
    /// <summary>
    /// Gets or sets the role value.
    /// </summary>
    public string? Role { get; set; }
    /// <summary>
    /// Gets or sets the permission value.
    /// </summary>
    public string? Permission { get; set; }
    /// <summary>
    /// Gets or sets the scope type value.
    /// </summary>
    public string? ScopeType { get; set; }
    /// <summary>
    /// Gets or sets the scope id value.
    /// </summary>
    public string? ScopeId { get; set; }
    /// <summary>
    /// Gets or sets the tenant id value.
    /// </summary>
    public Guid? TenantId { get; set; }
}
