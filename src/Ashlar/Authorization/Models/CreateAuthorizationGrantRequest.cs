namespace Ashlar.Authorization.Models;

public sealed record CreateAuthorizationGrantRequest(
    Guid UserId,
    Guid? TenantId = null,
    string? ScopeType = null,
    string? ScopeId = null,
    string? Role = null,
    string? Permission = null,
    DateTimeOffset? ExpiresAt = null,
    string? Metadata = null);
