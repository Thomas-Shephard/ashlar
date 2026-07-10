using Ashlar.Auditing;

namespace Ashlar.Authorization.Models;

/// <summary>Actor-bound request to create one authorization grant.</summary>
/// <remarks>The actor contains an Ashlar-issued fresh MFA proof and current session. The service verifies the proof, audit actor, host authorization, and exact target scope before mutation.</remarks>
public sealed record CreateAuthorizationGrantRequest
{
    /// <summary>Creates an app-facing grant request bound to an authenticated actor and explicit target scope.</summary>
    /// <param name="userId">User receiving the grant.</param><param name="actor">Authenticated actor, current session, and fresh proof.</param><param name="audit">Required audit metadata whose actor must match <paramref name="actor"/>.</param>
    /// <param name="tenant">Explicit tenant or global target scope.</param><param name="includeAllTenants">Whether every tenant is targeted; grant creation rejects this because one grant has one scope.</param>
    /// <param name="scopeType">Optional resource type.</param><param name="scopeId">Optional resource identifier.</param><param name="role">Role to grant.</param>
    /// <param name="permission">Permission to grant.</param><param name="expiresAt">Optional expiry time.</param><param name="metadata">Optional provider-neutral JSON metadata.</param>
    public CreateAuthorizationGrantRequest(Guid userId, AccountSecurityActorContext actor, AuditContext audit, TenantContext? tenant = null,
        bool includeAllTenants = false, string? scopeType = null, string? scopeId = null, string? role = null,
        string? permission = null, DateTimeOffset? expiresAt = null, string? metadata = null)
    {
        ArgumentNullException.ThrowIfNull(actor);
        ArgumentNullException.ThrowIfNull(audit);
        AdministrationScopeValidation.ThrowIfInvalidScope(tenant, includeAllTenants);
        UserId = userId; Actor = actor; TenantId = tenant?.TenantId; IncludeAllTenants = includeAllTenants;
        Audit = audit; ScopeType = scopeType; ScopeId = scopeId; Role = role; Permission = permission;
        ExpiresAt = expiresAt; Metadata = metadata;
    }

    internal CreateAuthorizationGrantRequest(Guid UserId, AuditContext Audit, Guid? TenantId = null,
        string? ScopeType = null, string? ScopeId = null, string? Role = null, string? Permission = null,
        DateTimeOffset? ExpiresAt = null, string? Metadata = null)
    {
        this.UserId = UserId; this.Audit = Audit; this.TenantId = TenantId; this.ScopeType = ScopeType;
        this.ScopeId = ScopeId; this.Role = Role; this.Permission = Permission; this.ExpiresAt = ExpiresAt;
        this.Metadata = Metadata; IsInfrastructureMutation = true;
    }

    /// <summary>Gets the user receiving the grant.</summary>
    public Guid UserId { get; }
    /// <summary>Gets the validated actor capability supplied by an app caller.</summary>
    public AccountSecurityActorContext? Actor { get; }
    /// <summary>Gets required audit metadata whose actor must match <see cref="Actor"/>.</summary>
    public AuditContext Audit { get; }
    /// <summary>Gets the exact tenant identifier, or <see langword="null"/> for global scope.</summary>
    public Guid? TenantId { get; }
    /// <summary>Gets whether all tenant scopes were requested.</summary>
    public bool IncludeAllTenants { get; }
    /// <summary>Gets the optional resource type.</summary>
    public string? ScopeType { get; }
    /// <summary>Gets the optional resource identifier.</summary>
    public string? ScopeId { get; }
    /// <summary>Gets the role to grant.</summary>
    public string? Role { get; }
    /// <summary>Gets the permission to grant.</summary>
    public string? Permission { get; }
    /// <summary>Gets the optional grant expiry.</summary>
    public DateTimeOffset? ExpiresAt { get; }
    /// <summary>Gets optional provider-neutral JSON metadata.</summary>
    public string? Metadata { get; }
    internal bool IsInfrastructureMutation { get; }
}
