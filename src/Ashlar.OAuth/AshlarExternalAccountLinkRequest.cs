using Ashlar.Identity.Models.Mfa;
using Ashlar.Identity.Models.Tenants;
using Microsoft.AspNetCore.Authentication;

namespace Ashlar.OAuth;

/// <summary>
/// Request parameters for self-service external account linking.
/// </summary>
/// <param name="AuthenticateResult">ASP.NET Core external authentication ticket validated by the configured provider middleware.</param>
/// <param name="FreshMfaProof">Ashlar-issued fresh MFA proof for the current authenticated session. Obtain it from <c>IStepUpAuthenticationService.CreateFreshMfaProof</c>; do not bind it from request JSON.</param>
/// <param name="CurrentSessionId">Current Ashlar session id from the authenticated request. It must match <paramref name="FreshMfaProof" />.</param>
/// <param name="Tenant">Tenant scope for the linking mutation. Use <see cref="TenantContext.Global" /> for global users.</param>
/// <param name="CredentialMetadata">Optional non-secret credential metadata to store with the link. Do not pass access tokens, refresh tokens, ID tokens, authorization codes, cookies, or raw claim payloads.</param>
public sealed record AshlarExternalAccountLinkRequest(
    AuthenticateResult AuthenticateResult,
    FreshMfaVerificationProof? FreshMfaProof,
    Guid? CurrentSessionId,
    TenantContext Tenant,
    string? CredentialMetadata = null);
