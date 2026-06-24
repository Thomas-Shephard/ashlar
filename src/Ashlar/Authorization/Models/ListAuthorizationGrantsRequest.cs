namespace Ashlar.Authorization.Models;

/// <summary>
/// Request to list authorization grants for a user, tenant boundary, and optional scope.
/// </summary>
/// <param name="UserId">The user whose grants are listed.</param>
/// <param name="TenantId">Tenant boundary for the query, or <see langword="null" /> for global grants.</param>
/// <param name="ScopeType">Optional resource type filter.</param>
/// <param name="ScopeId">Optional resource identifier within <paramref name="ScopeType" />.</param>
/// <param name="ActiveOnly">Whether revoked and expired grants should be omitted.</param>
/// <param name="ExactMatch">Whether scope filters must match exactly instead of allowing broader grants. Tenant matching is always exact.</param>
public sealed record ListAuthorizationGrantsRequest(
    Guid UserId,
    Guid? TenantId = null,
    string? ScopeType = null,
    string? ScopeId = null,
    bool ActiveOnly = false,
    bool ExactMatch = false);
