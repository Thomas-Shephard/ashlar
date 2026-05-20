namespace Ashlar.Authorization.Models;

/// <summary>
/// Represents the authorization evaluation request data model.
/// </summary>
/// <param name="UserId">The user id value.</param>
/// <param name="Permission">The permission value.</param>
/// <param name="Role">The role value.</param>
/// <param name="TenantId">The tenant id value.</param>
/// <param name="ScopeType">The scope type value.</param>
/// <param name="ScopeId">The scope id value.</param>
public sealed record AuthorizationEvaluationRequest(
    Guid UserId,
    string? Permission = null,
    string? Role = null,
    Guid? TenantId = null,
    string? ScopeType = null,
    string? ScopeId = null);


