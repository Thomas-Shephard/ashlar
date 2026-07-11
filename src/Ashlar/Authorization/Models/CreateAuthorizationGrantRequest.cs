using Ashlar.Auditing;

namespace Ashlar.Authorization.Models;

/// <summary>Actor-bound request to create one authorization grant.</summary>
/// <remarks>The actor contains an Ashlar-issued fresh MFA proof and current session. The service verifies the proof, audit actor, host authorization, and exact target scope before mutation.</remarks>
public sealed record CreateAuthorizationGrantRequest
{
    /// <summary>Creates an app-facing grant request bound to an authenticated actor and explicit target scope.</summary>
    /// <param name="userId">User receiving the grant.</param><param name="actor">Authenticated actor, current session, and fresh proof.</param><param name="audit">Required audit metadata whose actor must match <paramref name="actor"/>.</param>
    /// <param name="tenant">Explicit tenant or global target scope.</param>
    /// <param name="grant">Role or permission and optional resource constraints.</param>
    /// <param name="includeAllTenants">Whether every tenant is targeted; grant creation rejects this because one grant has one scope.</param>
    public CreateAuthorizationGrantRequest(Guid userId, AccountSecurityActorContext? actor, AuditContext? audit,
        TenantContext? tenant, AuthorizationGrantSpecification? grant, bool includeAllTenants = false)
    {
        UserId = userId; Actor = actor; TenantId = tenant?.TenantId; IncludeAllTenants = includeAllTenants;
        IsScopeInvalid = tenant is null || includeAllTenants;
        IsGrantMissing = grant is null; Audit = audit; ScopeType = grant?.ScopeType; ScopeId = grant?.ScopeId;
        Role = grant?.Role; Permission = grant?.Permission; ExpiresAt = grant?.ExpiresAt; Metadata = grant?.Metadata;
    }

    /// <summary>Creates an actor-bound permission grant without resource constraints.</summary>
    /// <param name="userId">User receiving the permission.</param>
    /// <param name="actor">Authenticated actor, current session, and fresh proof.</param>
    /// <param name="audit">Required audit metadata whose actor must match <paramref name="actor"/>.</param>
    /// <param name="tenant">Explicit tenant or global target scope.</param>
    /// <param name="includeAllTenants">Whether every tenant is targeted; grant creation rejects this because one grant has one scope.</param>
    /// <param name="permission">Permission to grant.</param>
    public CreateAuthorizationGrantRequest(Guid userId, AccountSecurityActorContext? actor, AuditContext? audit,
        TenantContext? tenant = null, bool includeAllTenants = false, string? permission = null)
        : this(userId, actor, audit, tenant, new AuthorizationGrantSpecification { Permission = permission }, includeAllTenants)
    { }

    internal CreateAuthorizationGrantRequest(Guid userId, AuditContext audit, Guid? tenantId, AuthorizationGrantSpecification grant)
    {
        UserId = userId; Audit = audit; TenantId = tenantId; ScopeType = grant.ScopeType;
        ScopeId = grant.ScopeId; Role = grant.Role; Permission = grant.Permission; ExpiresAt = grant.ExpiresAt;
        Metadata = grant.Metadata; IsInfrastructureMutation = true;
    }

    internal CreateAuthorizationGrantRequest(Guid UserId, AuditContext Audit, Guid? TenantId = null,
        string? ScopeType = null, string? ScopeId = null, string? Role = null, string? Permission = null)
        : this(UserId, Audit, TenantId, new AuthorizationGrantSpecification
        {
            ScopeType = ScopeType,
            ScopeId = ScopeId,
            Role = Role,
            Permission = Permission
        })
    { }

    internal CreateAuthorizationGrantRequest(Guid UserId, AuditContext Audit, string? Permission, string? Metadata)
        : this(UserId, Audit, null, new AuthorizationGrantSpecification { Permission = Permission, Metadata = Metadata }) { }

    /// <summary>Gets the user receiving the grant.</summary>
    public Guid UserId { get; }
    /// <summary>Gets the validated actor capability supplied by an app caller.</summary>
    public AccountSecurityActorContext? Actor { get; }
    /// <summary>Gets required audit metadata whose actor must match <see cref="Actor"/>.</summary>
    public AuditContext? Audit { get; }
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
    internal bool IsScopeInvalid { get; }
    internal bool IsGrantMissing { get; }
}
