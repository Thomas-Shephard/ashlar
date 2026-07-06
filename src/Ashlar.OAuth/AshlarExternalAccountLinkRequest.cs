using Ashlar.Identity.Models.Mfa;
using Ashlar.Identity.Models.Tenants;
using Microsoft.AspNetCore.Authentication;

namespace Ashlar.OAuth;

internal sealed record AshlarExternalAccountLinkRequest(
    AuthenticateResult AuthenticateResult,
    FreshMfaVerificationProof? FreshMfaProof,
    Guid? CurrentSessionId,
    TenantContext Tenant,
    string? CredentialMetadata = null);
