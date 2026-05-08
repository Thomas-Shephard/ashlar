namespace Ashlar.Authorization.Models;

public sealed record ListAuthorizationGrantsRequest(
    Guid UserId,
    Guid? TenantId = null,
    string? ScopeType = null,
    string? ScopeId = null,
    bool ActiveOnly = false,
    bool ExactMatch = false);
