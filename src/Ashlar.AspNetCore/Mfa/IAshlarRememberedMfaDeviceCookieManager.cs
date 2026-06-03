using Microsoft.AspNetCore.Http;

namespace Ashlar.AspNetCore.Mfa;

/// <summary>
/// Manages ASP.NET Core cookie transport for remembered MFA device tokens.
/// </summary>
public interface IAshlarRememberedMfaDeviceCookieManager
{
    /// <summary>
    /// Creates a remembered MFA device after a successful fresh MFA ceremony and writes the raw token to the response cookie.
    /// </summary>
    /// <param name="httpContext">The current HTTP request context.</param>
    /// <param name="context">The authentication context from the fresh MFA ceremony.</param>
    /// <param name="mfaResult">The successful MFA authentication result.</param>
    /// <param name="request">Optional creation metadata. When omitted, request metadata is derived from the authentication context.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>Safe remembered device metadata. The raw token is written only to the response cookie.</returns>
    Task<RememberedMfaDeviceSummary> IssueAfterSuccessfulMfaAsync(
        HttpContext httpContext,
        AuthenticationContext context,
        MfaAuthenticationResult mfaResult,
        CreateRememberedMfaDeviceRequest? request = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Reads the remembered MFA device cookie and returns an authentication context enriched with the raw token when present.
    /// </summary>
    /// <param name="httpContext">The current HTTP request context.</param>
    /// <param name="context">The authentication context to enrich.</param>
    /// <returns>The original context or a copy containing the remembered MFA device token item.</returns>
    AuthenticationContext EnrichContext(HttpContext httpContext, AuthenticationContext context);

    /// <summary>
    /// Clears the remembered MFA device cookie.
    /// </summary>
    /// <param name="httpContext">The current HTTP request context.</param>
    void Clear(HttpContext httpContext);

    /// <summary>
    /// Revokes the current remembered MFA device when the cookie validates for the supplied user, then clears the cookie.
    /// </summary>
    /// <param name="httpContext">The current HTTP request context.</param>
    /// <param name="userId">The user that owns the current request.</param>
    /// <param name="tenant">Optional tenant scope for validation and revocation.</param>
    /// <param name="reason">Optional revocation reason.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns><see langword="true" /> when a remembered device was revoked.</returns>
    Task<bool> RevokeCurrentAsync(
        HttpContext httpContext,
        Guid userId,
        TenantContext? tenant = null,
        string? reason = null,
        CancellationToken cancellationToken = default);
}
