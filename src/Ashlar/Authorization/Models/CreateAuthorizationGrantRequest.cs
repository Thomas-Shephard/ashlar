using Ashlar.Auditing;

namespace Ashlar.Authorization.Models;

/// <summary>Request to create one authorization grant.</summary>
public sealed record CreateAuthorizationGrantRequest
{
    /// <summary>Creates a grant request with an explicit target scope.</summary>
    /// <param name="userId">User receiving the grant.</param>
    /// <param name="tenant">Explicit tenant or global target scope.</param>
    /// <param name="grant">Role or permission and optional resource constraints.</param>
    /// <param name="includeAllTenants">Whether every tenant is targeted; grant creation rejects this because one grant has one scope.</param>
    public CreateAuthorizationGrantRequest(Guid userId, TenantContext? tenant,
        AuthorizationGrantSpecification? grant, bool includeAllTenants)
    {
        UserId = userId; TenantId = tenant?.TenantId; IncludeAllTenants = includeAllTenants;
        IsScopeInvalid = tenant is null || includeAllTenants;
        IsGrantMissing = grant is null; ScopeType = grant?.ScopeType; ScopeId = grant?.ScopeId;
        Role = grant?.Role; Permission = grant?.Permission; ExpiresAt = grant?.ExpiresAt; Metadata = grant?.Metadata;
    }

    /// <summary>Creates a permission grant without resource constraints.</summary>
    /// <param name="userId">User receiving the permission.</param>
    /// <param name="tenant">Explicit tenant or global target scope.</param>
    /// <param name="includeAllTenants">Whether every tenant is targeted; grant creation rejects this because one grant has one scope.</param>
    /// <param name="permission">Permission to grant.</param>
    public CreateAuthorizationGrantRequest(Guid userId, TenantContext? tenant = null,
        bool includeAllTenants = false, string? permission = null)
        : this(userId, tenant, new AuthorizationGrantSpecification { Permission = permission }, includeAllTenants)
    { }

    internal CreateAuthorizationGrantRequest(Guid userId, AuditContext audit, Guid? tenantId, AuthorizationGrantSpecification grant)
    {
        UserId = userId; BootstrapAudit = audit; TenantId = tenantId; ScopeType = grant.ScopeType;
        ScopeId = grant.ScopeId; Role = grant.Role; Permission = grant.Permission; ExpiresAt = grant.ExpiresAt;
        Metadata = grant.Metadata;
    }

    /// <summary>Gets the user receiving the grant.</summary>
    public Guid UserId { get; }
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
    internal AuditContext? BootstrapAudit { get; }
    internal bool IsScopeInvalid { get; }
    internal bool IsGrantMissing { get; }
}
