namespace Ashlar.Authorization.Models;

/// <summary>
/// Request to evaluate whether a user has a matching authorization grant.
/// </summary>
/// <param name="UserId">The user whose grants are evaluated.</param>
/// <param name="Permission">Permission to require. Callers should supply either <paramref name="Permission" /> or <paramref name="Role" />.</param>
/// <param name="Role">Role to require. Callers should supply either <paramref name="Role" /> or <paramref name="Permission" />.</param>
/// <param name="TenantId">Tenant boundary for the decision, or <see langword="null" /> for global grants.</param>
/// <param name="ScopeType">Optional resource type required by the decision.</param>
/// <param name="ScopeId">Optional resource identifier within <paramref name="ScopeType" />.</param>
public sealed record AuthorizationEvaluationRequest(
    Guid UserId,
    string? Permission = null,
    string? Role = null,
    Guid? TenantId = null,
    string? ScopeType = null,
    string? ScopeId = null);
