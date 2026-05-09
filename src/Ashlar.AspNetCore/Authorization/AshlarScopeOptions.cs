namespace Ashlar.AspNetCore.Authorization;

/// <summary>
/// Configures how scope information is resolved for an Ashlar authorization requirement.
/// </summary>
public sealed class AshlarScopeOptions
{
    /// <summary>
    /// Gets or sets the fixed scope type.
    /// </summary>
    public string? ScopeType { get; set; }

    /// <summary>
    /// Gets or sets the name of the route value to use as the scope ID.
    /// </summary>
    public string? ScopeIdRouteValueName { get; set; }

    /// <summary>
    /// Gets or sets a fixed scope ID.
    /// </summary>
    public string? FixedScopeId { get; set; }

    /// <summary>
    /// Gets or sets the name of the route value or claim type to use as the tenant ID.
    /// </summary>
    public string? TenantIdSource { get; set; }

    /// <summary>
    /// Gets or sets whether the <see cref="TenantIdSource"/> is a route value (default) or a claim type.
    /// </summary>
    public bool UseClaimForTenantId { get; set; }
}
