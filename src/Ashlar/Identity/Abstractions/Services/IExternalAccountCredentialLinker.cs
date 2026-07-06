using Ashlar.Auditing;

namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Links externally validated sign-in credentials to the current user through Ashlar's self-service account-security boundary.
/// </summary>
public interface IExternalAccountCredentialLinker
{
    /// <summary>
    /// Links an external provider credential to the current user after validating tenant ownership and operation-bound fresh MFA.
    /// </summary>
    /// <param name="request">The validated external credential and self-service account-security context.</param>
    /// <param name="cancellationToken">A token that can cancel linking.</param>
    /// <returns>Success when the credential is linked; otherwise, a stable failure describing why linking was rejected.</returns>
    Task<Result> LinkExternalAccountCredentialAsync(ExternalAccountCredentialLinkRequest request, CancellationToken cancellationToken = default);
}

/// <summary>
/// Request to link an externally validated sign-in credential to the current user.
/// </summary>
/// <param name="CurrentUserId">The currently authenticated Ashlar user that must own the credential.</param>
/// <param name="Assertion">Assertion mapped from a trusted external authentication ticket.</param>
/// <param name="Provider">Ashlar authenticator that owns the credential format.</param>
/// <param name="FreshMfaProof">Ashlar-issued fresh MFA proof minted for <c>external-account-linking</c>.</param>
/// <param name="CurrentSessionId">Current Ashlar session id from the authenticated request.</param>
/// <param name="Tenant">Tenant scope that must match both the current user and the fresh proof. Use <see cref="TenantContext.Global" /> for global users.</param>
/// <param name="Audit">Caller audit metadata for the account-security mutation.</param>
/// <param name="CredentialMetadata">Optional non-secret credential metadata. Do not include tokens, authorization codes, cookies, or raw claim payloads.</param>
public sealed record ExternalAccountCredentialLinkRequest(
    Guid CurrentUserId,
    IAuthenticationAssertion Assertion,
    IAuthenticationProvider Provider,
    FreshMfaVerificationProof? FreshMfaProof,
    Guid? CurrentSessionId,
    TenantContext Tenant,
    AuditContext? Audit = null,
    string? CredentialMetadata = null);
