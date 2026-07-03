using Ashlar.Auditing;

namespace Ashlar.Identity.Providers.RecoveryCode;

/// <summary>
/// Represents a request to generate new recovery codes.
/// </summary>
public sealed record RecoveryCodeGenerationRequest
{
    /// <summary>
    /// Fresh MFA proof for the current authenticated session. Obtain it from <c>IStepUpAuthenticationService.CreateFreshMfaProof</c>; do not bind it from request JSON.
    /// </summary>
    public FreshMfaVerificationProof? FreshMfaProof { get; init; }
    /// <summary>
    /// Current Ashlar session ID from the authenticated request. It must match <see cref="FreshMfaProof" />.
    /// </summary>
    public Guid? CurrentSessionId { get; init; }

    /// <summary>
    /// Whether existing recovery codes should be revoked before generating new ones.
    /// Defaults to <c><see langword="true" /></c>.
    /// </summary>
    public bool ReplaceExisting { get; init; } = true;

    /// <summary>
    /// Number of codes to generate. If <see langword="null" />, the configured default in <see cref="RecoveryCodeOptions"/> is used.
    /// </summary>
    public int? CodeCount { get; init; }

    /// <summary>
    /// Duration after which the codes expire. If <see langword="null" />, the configured default in <see cref="RecoveryCodeOptions"/> is used.
    /// </summary>
    public TimeSpan? ExpiresAfter { get; init; }

    /// <summary>
    /// Tenant scope for recovery-code generation, or <see langword="null" /> to use <see cref="TenantContext.Global" />.
    /// </summary>
    public TenantContext? Tenant { get; init; }

    /// <summary>
    /// Audit metadata describing who requested recovery-code generation.
    /// </summary>
    public AuditContext? Audit { get; init; }
}

/// <summary>
/// Request to revoke recovery codes for the authenticated account owner.
/// </summary>
public sealed record RevokeRecoveryCodesRequest
{
    /// <summary>
    /// Fresh MFA proof for the current authenticated session. Obtain it from <c>IStepUpAuthenticationService.CreateFreshMfaProof</c>; do not bind it from request JSON.
    /// </summary>
    public FreshMfaVerificationProof? FreshMfaProof { get; init; }
    /// <summary>
    /// Current Ashlar session ID from the authenticated request. It must match <see cref="FreshMfaProof" />.
    /// </summary>
    public Guid? CurrentSessionId { get; init; }

    /// <summary>
    /// Optional provider-neutral, display-safe audit reason for revocation.
    /// </summary>
    public string? Reason { get; init; }

    /// <summary>
    /// Tenant scope for recovery-code revocation, or <see langword="null" /> to use <see cref="TenantContext.Global" />.
    /// </summary>
    public TenantContext? Tenant { get; init; }

    /// <summary>
    /// Audit metadata describing who requested recovery-code revocation.
    /// </summary>
    public AuditContext? Audit { get; init; }
}
