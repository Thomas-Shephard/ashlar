using Ashlar.Auditing;

namespace Ashlar.Identity.Models.Totp;

/// <summary>
/// Contains the secret material needed to complete TOTP enrollment.
/// </summary>
/// <param name="SharedSecret">Raw shared secret for the authenticator app. Show it only during enrollment and do not log it.</param>
/// <param name="AuthenticatorUri">Provisioning URI for authenticator apps. Treat it as sensitive because it embeds the shared secret.</param>
public sealed record TotpEnrollment(
    string SharedSecret,
    string AuthenticatorUri);

/// <summary>
/// Result of a verified TOTP enrollment.
/// </summary>
/// <param name="UserId">The account owner whose TOTP credential was verified and enrolled.</param>
/// <param name="StepUpAuthenticationResult">Ashlar-verified MFA result for self-service enrollment.</param>
public sealed record TotpEnrollmentCompletionResult(
    Guid UserId,
    MfaAuthenticationResult? StepUpAuthenticationResult);

/// <summary>Actor and verification context required for self-service TOTP enrollment.</summary>
public sealed record TotpEnrollmentVerificationContext
{
    /// <summary>Creates an actor-bound enrollment context with exactly one fresh proof.</summary>
    /// <param name="actorUserId">Authenticated actor and target user.</param>
    /// <param name="tenant">Explicit actor and target scope.</param>
    /// <param name="currentSessionId">Current authenticated session.</param>
    /// <param name="audit">Required audit metadata.</param>
    /// <param name="freshMfaProof">Ashlar-issued MFA proof.</param>
    /// <param name="freshPrimaryAuthenticationProof">Ashlar-issued primary proof for first enrollment.</param>
    public TotpEnrollmentVerificationContext(Guid actorUserId, TenantContext tenant, Guid currentSessionId,
        AuditContext audit, FreshMfaVerificationProof? freshMfaProof = null,
        FreshPrimaryAuthenticationProof? freshPrimaryAuthenticationProof = null)
    {
        TotpRequestValidation.Validate(actorUserId, tenant, currentSessionId, audit);
        TotpRequestValidation.ValidateProofs(freshMfaProof, freshPrimaryAuthenticationProof);
        ActorUserId = actorUserId; Tenant = tenant; CurrentSessionId = currentSessionId; Audit = audit;
        FreshMfaProof = freshMfaProof; FreshPrimaryAuthenticationProof = freshPrimaryAuthenticationProof;
    }

    /// <summary>Gets the authenticated actor.</summary>
    public Guid ActorUserId { get; }
    /// <summary>Gets the explicit actor and target tenant scope.</summary>
    public TenantContext Tenant { get; }
    /// <summary>Gets the current authenticated session.</summary>
    public Guid CurrentSessionId { get; }
    /// <summary>Gets required audit metadata.</summary>
    public AuditContext Audit { get; }
    /// <summary>Gets fresh MFA proof when an MFA factor exists.</summary>
    public FreshMfaVerificationProof? FreshMfaProof { get; }
    /// <summary>Gets fresh primary-authentication proof for first MFA enrollment.</summary>
    public FreshPrimaryAuthenticationProof? FreshPrimaryAuthenticationProof { get; }
}

/// <summary>
/// Request to begin self-service TOTP enrollment for the authenticated account owner.
/// </summary>
/// <param name="ActorUserId">Authenticated user performing the self-service operation. This user owns the pending TOTP enrollment.</param>
/// <param name="Issuer">Issuer label shown by authenticator applications.</param>
/// <param name="AccountName">Account label shown by authenticator applications.</param>
public sealed record StartTotpEnrollmentRequest
{
    internal StartTotpEnrollmentRequest(Guid actorUserId, string issuer, string accountName)
    {
        ActorUserId = actorUserId; Issuer = issuer; AccountName = accountName;
        Tenant = TenantContext.Global; CurrentSessionId = Guid.Empty; Audit = new AuditContext(actorUserId);
    }
    /// <summary>Creates an actor-bound TOTP enrollment request.</summary>
    /// <param name="verification">Actor and fresh-verification context.</param>
    /// <param name="issuer">Authenticator issuer.</param>
    /// <param name="accountName">Authenticator account label.</param>
    public StartTotpEnrollmentRequest(TotpEnrollmentVerificationContext verification, string issuer, string accountName)
    {
        ArgumentNullException.ThrowIfNull(verification);
        ActorUserId = verification.ActorUserId; Issuer = issuer; AccountName = accountName; Tenant = verification.Tenant;
        CurrentSessionId = verification.CurrentSessionId; Audit = verification.Audit; FreshMfaProof = verification.FreshMfaProof;
        FreshPrimaryAuthenticationProof = verification.FreshPrimaryAuthenticationProof;
    }
    /// <summary>Gets the authenticated actor.</summary>
    public Guid ActorUserId { get; }
    /// <summary>Gets the authenticator issuer label.</summary>
    public string Issuer { get; }
    /// <summary>Gets the authenticator account label.</summary>
    public string AccountName { get; }
    /// <summary>Gets the explicit actor and target tenant scope.</summary>
    public TenantContext Tenant { get; init; }
    /// <summary>Gets the current authenticated session.</summary>
    public Guid CurrentSessionId { get; init; }
    /// <summary>Gets required audit metadata.</summary>
    public AuditContext Audit { get; init; }
    /// <summary>Gets fresh MFA proof when an MFA factor exists.</summary>
    public FreshMfaVerificationProof? FreshMfaProof { get; init; }
    /// <summary>Gets fresh primary-authentication proof for first MFA enrollment.</summary>
    public FreshPrimaryAuthenticationProof? FreshPrimaryAuthenticationProof { get; init; }
}

/// <summary>
/// Request to verify a pending self-service TOTP enrollment for the authenticated account owner.
/// </summary>
/// <param name="ActorUserId">Authenticated user performing the self-service operation. This user owns the finalized TOTP credential.</param>
/// <param name="SharedSecret">Raw shared secret from enrollment setup. Do not log this value.</param>
/// <param name="Code">TOTP code supplied by the user. Do not log this value.</param>
public sealed record VerifyTotpEnrollmentRequest
{
    internal VerifyTotpEnrollmentRequest(Guid actorUserId, string sharedSecret, string code)
    {
        ActorUserId = actorUserId; SharedSecret = sharedSecret; Code = code;
        Tenant = TenantContext.Global; CurrentSessionId = Guid.Empty; Audit = new AuditContext(actorUserId);
    }
    /// <summary>Creates an actor-bound TOTP enrollment completion request.</summary>
    /// <param name="verification">Actor and fresh-verification context.</param>
    /// <param name="sharedSecret">Pending shared secret.</param>
    /// <param name="code">Authenticator code.</param>
    public VerifyTotpEnrollmentRequest(TotpEnrollmentVerificationContext verification, string sharedSecret, string code)
    {
        ArgumentNullException.ThrowIfNull(verification);
        ActorUserId = verification.ActorUserId; SharedSecret = sharedSecret; Code = code; Tenant = verification.Tenant;
        CurrentSessionId = verification.CurrentSessionId; Audit = verification.Audit; FreshMfaProof = verification.FreshMfaProof;
        FreshPrimaryAuthenticationProof = verification.FreshPrimaryAuthenticationProof;
    }
    /// <summary>Gets the authenticated actor.</summary>
    public Guid ActorUserId { get; }
    /// <summary>Gets the pending TOTP shared secret.</summary>
    public string SharedSecret { get; }
    /// <summary>Gets the verification code.</summary>
    public string Code { get; }
    /// <summary>Gets the explicit actor and target tenant scope.</summary>
    public TenantContext Tenant { get; init; }
    /// <summary>Gets the current authenticated session.</summary>
    public Guid CurrentSessionId { get; init; }
    /// <summary>Gets required audit metadata.</summary>
    public AuditContext Audit { get; init; }
    /// <summary>Gets fresh MFA proof when an MFA factor exists.</summary>
    public FreshMfaVerificationProof? FreshMfaProof { get; init; }
    /// <summary>Gets fresh primary-authentication proof for first MFA enrollment.</summary>
    public FreshPrimaryAuthenticationProof? FreshPrimaryAuthenticationProof { get; init; }
}

/// <summary>
/// Request to disable the authenticated account owner's self-service TOTP credential.
/// </summary>
/// <param name="ActorUserId">Authenticated user performing the self-service operation. This user owns the TOTP credential being disabled.</param>
public sealed record DisableTotpRequest
{
    internal DisableTotpRequest(Guid actorUserId)
    {
        ActorUserId = actorUserId; Tenant = TenantContext.Global; CurrentSessionId = Guid.Empty;
        FreshMfaProof = null!; Audit = new AuditContext(actorUserId);
    }
    /// <summary>Creates an actor-bound TOTP disable request.</summary>
    /// <param name="actorUserId">Authenticated actor and target user.</param><param name="tenant">Explicit actor and target scope.</param>
    /// <param name="currentSessionId">Current authenticated session.</param><param name="freshMfaProof">Ashlar-issued MFA proof bound to the actor and current session.</param>
    /// <param name="audit">Required audit metadata.</param>
    public DisableTotpRequest(Guid actorUserId, TenantContext tenant, Guid currentSessionId,
        FreshMfaVerificationProof freshMfaProof, AuditContext audit)
    {
        TotpRequestValidation.Validate(actorUserId, tenant, currentSessionId, audit);
        ArgumentNullException.ThrowIfNull(freshMfaProof);
        ActorUserId = actorUserId; Tenant = tenant; CurrentSessionId = currentSessionId;
        FreshMfaProof = freshMfaProof; Audit = audit;
    }
    /// <summary>Gets the authenticated actor.</summary>
    public Guid ActorUserId { get; }
    /// <summary>Gets the explicit actor and target tenant scope.</summary>
    public TenantContext Tenant { get; init; }
    /// <summary>Gets the current authenticated session.</summary>
    public Guid CurrentSessionId { get; init; }
    /// <summary>Gets the fresh MFA proof.</summary>
    public FreshMfaVerificationProof FreshMfaProof { get; init; }
    /// <summary>Gets required audit metadata.</summary>
    public AuditContext Audit { get; init; }
}

file static class TotpRequestValidation
{
    public static void Validate(Guid actorUserId, TenantContext tenant, Guid currentSessionId, AuditContext audit)
    {
        if (actorUserId == Guid.Empty) throw new ArgumentException("Actor user ID cannot be empty.", nameof(actorUserId));
        ArgumentNullException.ThrowIfNull(tenant);
        if (currentSessionId == Guid.Empty) throw new ArgumentException("Current session ID cannot be empty.", nameof(currentSessionId));
        ArgumentNullException.ThrowIfNull(audit);
        if (audit.ActorUserId != actorUserId) throw new ArgumentException("Audit actor must match the authenticated actor.", nameof(audit));
    }

    public static void ValidateProofs(FreshMfaVerificationProof? mfaProof, FreshPrimaryAuthenticationProof? primaryProof)
    {
        if ((mfaProof is null) == (primaryProof is null)) throw new ArgumentException("Exactly one fresh verification proof is required.");
    }
}
