using Ashlar.AspNetCore.Authentication;
using Ashlar.Identity.Features.Mfa;
using Microsoft.AspNetCore.Http;

namespace Ashlar.AspNetCore.Mfa;

/// <summary>
/// Provides helpers for creating Ashlar fresh-MFA proof from ASP.NET Core requests.
/// </summary>
public static class AshlarFreshMfaProofHttpContextExtensions
{
    /// <summary>
    /// Creates self-service MFA management proof from the current Ashlar-validated session.
    /// </summary>
    /// <param name="httpContext">Current request context populated by Ashlar session authentication.</param>
    /// <param name="stepUp">Step-up service used to evaluate the validated session.</param>
    /// <param name="requirement">Freshness, provider, and factor requirement for the sensitive mutation.</param>
    /// <returns>Fresh MFA proof scoped to the current user, tenant, and session, or a failure when verification is missing or stale.</returns>
    /// <remarks>
    /// Claims, remembered-device cookies, and client-supplied booleans are not sufficient. The Ashlar session
    /// authentication handler must have validated the request and stored the current session in <see cref="HttpContext.Items" />.
    /// </remarks>
    public static Result<FreshMfaVerificationProof> CreateFreshMfaProof(
        this HttpContext httpContext,
        StepUpAuthenticationService stepUp,
        StepUpRequirement requirement)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(stepUp);
        ArgumentNullException.ThrowIfNull(requirement);

        if (httpContext.Items[AshlarHttpContextItems.ValidatedAuthenticationSession] is not ValidatedAuthenticationSession session)
        {
            return Result.Failure<FreshMfaVerificationProof>(AshlarFailureCodes.SessionNotFoundOrInactive);
        }

        return stepUp.CreateFreshMfaProof(session, requirement);
    }

    /// <summary>
    /// Creates first additional-verification factor bootstrap proof from the current Ashlar-validated session.
    /// </summary>
    /// <param name="httpContext">Current request context populated by Ashlar session authentication.</param>
    /// <param name="stepUp">Step-up service used to evaluate the validated session.</param>
    /// <param name="freshnessWindow">Maximum age of the current primary sign-in.</param>
    /// <param name="purpose">Optional operation purpose this proof is minted for.</param>
    /// <returns>Fresh primary-authentication proof scoped to the current user, tenant, and session, or a failure when sign-in is missing or stale.</returns>
    /// <remarks>
    /// This proof is for enrolling MFA when the account has no usable additional-verification factor.
    /// It is not fresh MFA and must not be accepted for replacing or disabling factors or managing recovery codes.
    /// </remarks>
    public static Result<FreshPrimaryAuthenticationProof> CreateFreshPrimaryAuthenticationProof(
        this HttpContext httpContext,
        StepUpAuthenticationService stepUp,
        TimeSpan freshnessWindow,
        string? purpose = null)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(stepUp);

        if (httpContext.Items[AshlarHttpContextItems.ValidatedAuthenticationSession] is not ValidatedAuthenticationSession session)
        {
            return Result.Failure<FreshPrimaryAuthenticationProof>(AshlarFailureCodes.SessionNotFoundOrInactive);
        }

        return stepUp.CreateFreshPrimaryAuthenticationProof(session, freshnessWindow, purpose);
    }
}
