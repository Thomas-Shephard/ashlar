namespace Ashlar.Authorization.Models;

public sealed record AuthorizationEvaluationRequest(
    Guid UserId,
    string? Permission = null,
    string? Role = null,
    Guid? TenantId = null,
    string? ScopeType = null,
    string? ScopeId = null);
