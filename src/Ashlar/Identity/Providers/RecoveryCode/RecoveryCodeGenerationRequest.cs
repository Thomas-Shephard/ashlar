using Ashlar.Auditing;

namespace Ashlar.Identity.Providers.RecoveryCode;

/// <summary>Actor-bound request to generate recovery codes for a target user.</summary>
public sealed record RecoveryCodeGenerationRequest : AccountSecurityAdministrationRequest
{
    /// <summary>Creates an authorized recovery-code generation request.</summary>
    /// <param name="targetUserId">The user receiving the recovery codes.</param>
    /// <param name="actorUserId">The authenticated actor.</param>
    /// <param name="actorTenant">The actor's authenticated tenant or global scope.</param>
    /// <param name="currentSessionId">The actor's current authenticated session.</param>
    /// <param name="freshMfaProof">Actor/session-bound fresh MFA proof.</param>
    /// <param name="audit">Required audit metadata whose actor matches <paramref name="actorUserId" />.</param>
    /// <param name="tenant">The explicit target tenant or global scope.</param>
    /// <param name="includeAllTenants">Whether target lookup may cross every tenant scope.</param>
    /// <param name="reason">An optional display-safe reason.</param>
    /// <param name="replaceExisting">Whether existing recovery codes are revoked before generation.</param>
    /// <param name="codeCount">Requested code count, or <see langword="null" /> for the configured default.</param>
    /// <param name="expiresAfter">Requested lifetime, or <see langword="null" /> for the configured default.</param>
    public RecoveryCodeGenerationRequest(
        Guid targetUserId,
        Guid actorUserId,
        TenantContext actorTenant,
        Guid currentSessionId,
        FreshMfaVerificationProof freshMfaProof,
        AuditContext audit,
        TenantContext? tenant = null,
        bool includeAllTenants = false,
        string? reason = null,
        bool replaceExisting = true,
        int? codeCount = null,
        TimeSpan? expiresAfter = null)
        : base(targetUserId, actorUserId, actorTenant, currentSessionId, freshMfaProof, audit, tenant, includeAllTenants, reason)
    {
        ReplaceExisting = replaceExisting;
        CodeCount = codeCount;
        ExpiresAfter = expiresAfter;
    }

    /// <summary>Gets whether existing recovery codes are revoked before generation.</summary>
    public bool ReplaceExisting { get; }

    /// <summary>Gets the requested code count, or <see langword="null" /> for the configured default.</summary>
    public int? CodeCount { get; }

    /// <summary>Gets the requested lifetime, or <see langword="null" /> for the configured default.</summary>
    public TimeSpan? ExpiresAfter { get; }
}

/// <summary>Actor-bound request to revoke all recovery codes for a target user.</summary>
public sealed record RevokeRecoveryCodesRequest : AccountSecurityAdministrationRequest
{
    /// <summary>Creates an authorized recovery-code revocation request.</summary>
    /// <param name="targetUserId">The user whose recovery codes are revoked.</param>
    /// <param name="actorUserId">The authenticated actor.</param>
    /// <param name="actorTenant">The actor's authenticated tenant or global scope.</param>
    /// <param name="currentSessionId">The actor's current authenticated session.</param>
    /// <param name="freshMfaProof">Actor/session-bound fresh MFA proof.</param>
    /// <param name="audit">Required audit metadata whose actor matches <paramref name="actorUserId" />.</param>
    /// <param name="tenant">The explicit target tenant or global scope.</param>
    /// <param name="includeAllTenants">Whether target lookup may cross every tenant scope.</param>
    /// <param name="reason">An optional display-safe reason.</param>
    public RevokeRecoveryCodesRequest(
        Guid targetUserId,
        Guid actorUserId,
        TenantContext actorTenant,
        Guid currentSessionId,
        FreshMfaVerificationProof freshMfaProof,
        AuditContext audit,
        TenantContext? tenant = null,
        bool includeAllTenants = false,
        string? reason = null)
        : base(targetUserId, actorUserId, actorTenant, currentSessionId, freshMfaProof, audit, tenant, includeAllTenants, reason)
    {
    }
}

internal sealed record RecoveryCodeGenerationExecutionRequest(
    AuditContext Audit,
    TenantContext? Tenant,
    bool IncludeAllTenants,
    string? Reason,
    bool ReplaceExisting,
    int? CodeCount,
    TimeSpan? ExpiresAfter);

internal sealed record RevokeRecoveryCodesExecutionRequest(
    AuditContext Audit,
    TenantContext? Tenant,
    bool IncludeAllTenants,
    string? Reason);
