namespace Ashlar.Authorization.Models;

/// <summary>
/// Result of evaluating a role or permission grant.
/// </summary>
/// <param name="Succeeded">Whether a currently active grant satisfied the request.</param>
/// <param name="MatchingGrant">Display-safe details for the grant that satisfied the request, when one was found.</param>
public sealed record AuthorizationEvaluationResult(bool Succeeded, MatchedAuthorizationGrantSummary? MatchingGrant)
{
    /// <summary>
    /// A failed authorization decision with no matching grant.
    /// </summary>
    public static AuthorizationEvaluationResult Failed { get; } = new(false, null);
}

/// <summary>
/// Safe matched-grant details returned from authorization evaluation.
/// </summary>
/// <param name="Id">Stable grant identifier.</param>
/// <param name="TenantId">Tenant scope for the grant, or <see langword="null" /> for a global grant.</param>
/// <param name="ScopeType">Resource type that constrains the grant, when present.</param>
/// <param name="ScopeId">Resource identifier that constrains the grant, when present.</param>
/// <param name="Role">Matched role value, when present.</param>
/// <param name="Permission">Matched permission value, when present.</param>
/// <param name="ExpiresAt">UTC time after which the grant no longer applies, when configured.</param>
public sealed record MatchedAuthorizationGrantSummary(
    Guid Id,
    Guid? TenantId,
    string? ScopeType,
    string? ScopeId,
    string? Role,
    string? Permission,
    DateTimeOffset? ExpiresAt);
