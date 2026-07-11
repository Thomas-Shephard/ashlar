namespace Ashlar.Authorization.Models;

/// <summary>Defines the role or permission and optional resource constraints for a new authorization grant.</summary>
public sealed record AuthorizationGrantSpecification
{
    /// <summary>Gets the optional resource type.</summary>
    public string? ScopeType { get; init; }
    /// <summary>Gets the optional resource identifier.</summary>
    public string? ScopeId { get; init; }
    /// <summary>Gets the role to grant.</summary>
    public string? Role { get; init; }
    /// <summary>Gets the permission to grant.</summary>
    public string? Permission { get; init; }
    /// <summary>Gets the optional expiry.</summary>
    public DateTimeOffset? ExpiresAt { get; init; }
    /// <summary>Gets optional provider-neutral JSON metadata.</summary>
    public string? Metadata { get; init; }
}
