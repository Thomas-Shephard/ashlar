using Ashlar.Auditing;

namespace Ashlar.Authorization.Models;

/// <summary>
/// Request to create an authorization grant for a user.
/// </summary>
/// <param name="UserId">The user that will receive the grant.</param>
/// <param name="Audit">Actor and request context to include in emitted security events. Grant creation is a privilege change and requires audit context.</param>
/// <param name="TenantId">Tenant boundary that bounds the grant, or <see langword="null" /> for a global grant.</param>
/// <param name="ScopeType">Optional resource type that further constrains the grant.</param>
/// <param name="ScopeId">Optional resource identifier within <paramref name="ScopeType" />.</param>
/// <param name="Role">Role to grant. Callers should supply either <paramref name="Role" /> or <paramref name="Permission" />.</param>
/// <param name="Permission">Permission to grant. Callers should supply either <paramref name="Permission" /> or <paramref name="Role" />.</param>
/// <param name="ExpiresAt">Optional time after which the grant should stop applying.</param>
/// <param name="Metadata">Provider-neutral administrative <paramref name="Metadata" />. Do not include secrets or credentials.</param>
/// <remarks>Callers must authorize the actor before creating grants; this request object does not perform that check. Service-layer mutation rejects a missing <paramref name="Audit" />.</remarks>
public sealed record CreateAuthorizationGrantRequest(
    Guid UserId,
    AuditContext Audit,
    Guid? TenantId = null,
    string? ScopeType = null,
    string? ScopeId = null,
    string? Role = null,
    string? Permission = null,
    DateTimeOffset? ExpiresAt = null,
    string? Metadata = null);
