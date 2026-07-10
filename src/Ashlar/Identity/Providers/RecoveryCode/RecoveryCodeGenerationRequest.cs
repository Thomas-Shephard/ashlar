using Ashlar.Auditing;

namespace Ashlar.Identity.Providers.RecoveryCode;

/// <summary>Options for a recovery-code generation operation.</summary>
/// <param name="ReplaceExisting">Whether existing recovery codes are revoked first.</param>
/// <param name="CodeCount">Requested code count, or <see langword="null" /> for the configured default.</param>
/// <param name="ExpiresAfter">Requested lifetime, or <see langword="null" /> for the configured default.</param>
public sealed record RecoveryCodeGenerationSettings(
    bool ReplaceExisting = true,
    int? CodeCount = null,
    TimeSpan? ExpiresAfter = null);

/// <summary>Actor-bound request to generate recovery codes for a target user.</summary>
public sealed record RecoveryCodeGenerationRequest : AccountSecurityAdministrationRequest
{
    /// <summary>Creates an authorized recovery-code generation request.</summary>
    /// <param name="targetUserId">The user receiving the recovery codes.</param>
    /// <param name="actor">Authenticated actor context.</param>
    /// <param name="tenant">The explicit target tenant or global scope.</param>
    /// <param name="includeAllTenants">Whether target lookup may cross every tenant scope.</param>
    /// <param name="reason">An optional display-safe reason.</param>
    /// <param name="settings">Generation-specific settings.</param>
    public RecoveryCodeGenerationRequest(
        Guid targetUserId,
        AccountSecurityActorContext actor,
        TenantContext? tenant = null,
        bool includeAllTenants = false,
        string? reason = null,
        RecoveryCodeGenerationSettings? settings = null)
        : base(targetUserId, actor, tenant, includeAllTenants, reason)
    {
        settings ??= new RecoveryCodeGenerationSettings();
        ReplaceExisting = settings.ReplaceExisting;
        CodeCount = settings.CodeCount;
        ExpiresAfter = settings.ExpiresAfter;
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
    /// <param name="actor">Authenticated actor context.</param>
    /// <param name="tenant">The explicit target tenant or global scope.</param>
    /// <param name="includeAllTenants">Whether target lookup may cross every tenant scope.</param>
    /// <param name="reason">An optional display-safe reason.</param>
    public RevokeRecoveryCodesRequest(
        Guid targetUserId,
        AccountSecurityActorContext actor,
        TenantContext? tenant = null,
        bool includeAllTenants = false,
        string? reason = null)
        : base(targetUserId, actor, tenant, includeAllTenants, reason)
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
