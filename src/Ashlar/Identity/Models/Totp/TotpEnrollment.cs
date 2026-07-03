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
/// Request to begin self-service TOTP enrollment for the authenticated account owner.
/// </summary>
/// <param name="ActorUserId">Authenticated user performing the self-service operation. This user owns the pending TOTP enrollment.</param>
/// <param name="Issuer">Issuer label shown by authenticator applications.</param>
/// <param name="AccountName">Account label shown by authenticator applications.</param>
public sealed record StartTotpEnrollmentRequest(Guid ActorUserId, string Issuer, string AccountName)
{
    /// <summary>Fresh MFA proof for the current authenticated session. Obtain it from <c>IStepUpAuthenticationService.CreateFreshMfaProof</c>; do not bind it from request JSON.</summary>
    public FreshMfaVerificationProof? FreshMfaProof { get; init; }
    /// <summary>Fresh primary-authentication proof for TOTP enrollment only when the account has no usable MFA factor. Obtain it from <c>IStepUpAuthenticationService.CreateFreshPrimaryAuthenticationProof</c>; do not bind it from request JSON.</summary>
    public FreshPrimaryAuthenticationProof? FreshPrimaryAuthenticationProof { get; init; }
    /// <summary>Current Ashlar session ID from the authenticated request. It must match the supplied fresh-verification proof.</summary>
    public Guid? CurrentSessionId { get; init; }
    /// <summary>Tenant scope for the enrollment. Omit or use <see cref="TenantContext.Global" /> for global users; this is not an all-tenant scope.</summary>
    public TenantContext? Tenant { get; init; }
    /// <summary>Audit metadata recorded with the enrollment attempt. Do not include TOTP secrets or codes.</summary>
    public AuditContext? Audit { get; init; }
}

/// <summary>
/// Request to verify a pending self-service TOTP enrollment for the authenticated account owner.
/// </summary>
/// <param name="ActorUserId">Authenticated user performing the self-service operation. This user owns the finalized TOTP credential.</param>
/// <param name="SharedSecret">Raw shared secret from enrollment setup. Do not log this value.</param>
/// <param name="Code">TOTP code supplied by the user. Do not log this value.</param>
public sealed record VerifyTotpEnrollmentRequest(Guid ActorUserId, string SharedSecret, string Code)
{
    /// <summary>Fresh MFA proof for the current authenticated session. Obtain it from <c>IStepUpAuthenticationService.CreateFreshMfaProof</c>; do not bind it from request JSON.</summary>
    public FreshMfaVerificationProof? FreshMfaProof { get; init; }
    /// <summary>Fresh primary-authentication proof for TOTP enrollment only when the account has no usable MFA factor. Obtain it from <c>IStepUpAuthenticationService.CreateFreshPrimaryAuthenticationProof</c>; do not bind it from request JSON.</summary>
    public FreshPrimaryAuthenticationProof? FreshPrimaryAuthenticationProof { get; init; }
    /// <summary>Current Ashlar session ID from the authenticated request. It must match the supplied fresh-verification proof.</summary>
    public Guid? CurrentSessionId { get; init; }
    /// <summary>Tenant scope for the enrollment. Omit or use <see cref="TenantContext.Global" /> for global users; this is not an all-tenant scope.</summary>
    public TenantContext? Tenant { get; init; }
    /// <summary>Audit metadata recorded with the enrollment attempt. Do not include TOTP secrets or codes.</summary>
    public AuditContext? Audit { get; init; }
}

/// <summary>
/// Request to disable the authenticated account owner's self-service TOTP credential.
/// </summary>
/// <param name="ActorUserId">Authenticated user performing the self-service operation. This user owns the TOTP credential being disabled.</param>
public sealed record DisableTotpRequest(Guid ActorUserId)
{
    /// <summary>Fresh MFA proof for the current authenticated session. Obtain it from <c>IStepUpAuthenticationService.CreateFreshMfaProof</c>; do not bind it from request JSON.</summary>
    public FreshMfaVerificationProof? FreshMfaProof { get; init; }
    /// <summary>Current Ashlar session ID from the authenticated request. It must match <see cref="FreshMfaProof" />.</summary>
    public Guid? CurrentSessionId { get; init; }
    /// <summary>Tenant scope for the credential. Omit or use <see cref="TenantContext.Global" /> for global users; this is not an all-tenant scope.</summary>
    public TenantContext? Tenant { get; init; }
    /// <summary>Audit metadata recorded with the disable attempt. Do not include TOTP secrets or codes.</summary>
    public AuditContext? Audit { get; init; }
}
