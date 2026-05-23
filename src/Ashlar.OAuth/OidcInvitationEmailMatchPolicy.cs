using System.Security.Claims;
using Ashlar.Identity.Models.Invitations;

namespace Ashlar.OAuth;

/// <summary>
/// Validates that a provider identity is allowed to accept a specific invitation.
/// </summary>
public interface IOidcInvitationEmailMatchPolicy
{
    /// <summary>
    /// Validates the provider identity against the invitation before the invitation token is consumed.
    /// </summary>
    /// <param name="context">The policy validation context.</param>
    /// <returns>The validation result.</returns>
    OidcInvitationEmailMatchResult Validate(OidcInvitationEmailMatchContext context);
}

/// <summary>
/// Default invitation email policy requiring a matching standard OIDC verified email claim.
/// </summary>
public sealed class StandardOidcVerifiedEmailMatchPolicy : IOidcInvitationEmailMatchPolicy
{
    /// <inheritdoc />
    public OidcInvitationEmailMatchResult Validate(OidcInvitationEmailMatchContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var email = context.Principal.FindFirstValue("email");
        if (string.IsNullOrWhiteSpace(email))
        {
            return OidcInvitationEmailMatchResult.EmailNotVerified();
        }

        if (!string.Equals(email.Trim(), context.Invitation.Email.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            return OidcInvitationEmailMatchResult.EmailMismatch();
        }

        var verified = context.Principal.FindFirstValue("email_verified");
        return string.Equals(verified, "true", StringComparison.OrdinalIgnoreCase) || string.Equals(verified, "1", StringComparison.Ordinal)
            ? OidcInvitationEmailMatchResult.Success()
            : OidcInvitationEmailMatchResult.EmailNotVerified();
    }
}

/// <summary>
/// Provides data needed to validate OIDC invite email matching.
/// </summary>
/// <param name="ProviderName">The configured Ashlar OIDC provider name.</param>
/// <param name="Principal">The validated OIDC principal.</param>
/// <param name="Invitation">The invitation acceptance preview.</param>
public sealed record OidcInvitationEmailMatchContext(
    string ProviderName,
    ClaimsPrincipal Principal,
    InvitationAcceptancePreview Invitation);

/// <summary>
/// Describes the result of an OIDC invite email policy check.
/// </summary>
/// <param name="Status">The registration status to use when validation fails, or <see langword="null" /> on success.</param>
public sealed record OidcInvitationEmailMatchResult(AshlarOidcInvitationRegistrationStatus? Status)
{
    /// <summary>
    /// Gets a value indicating whether validation succeeded.
    /// </summary>
    public bool Succeeded => Status == null;

    /// <summary>
    /// Creates a successful policy result.
    /// </summary>
    /// <returns>The policy result.</returns>
    public static OidcInvitationEmailMatchResult Success() => new((AshlarOidcInvitationRegistrationStatus?)null);

    /// <summary>
    /// Creates an email mismatch policy result.
    /// </summary>
    /// <returns>The policy result.</returns>
    public static OidcInvitationEmailMatchResult EmailMismatch() => new(AshlarOidcInvitationRegistrationStatus.EmailMismatch);

    /// <summary>
    /// Creates an email-not-verified policy result.
    /// </summary>
    /// <returns>The policy result.</returns>
    public static OidcInvitationEmailMatchResult EmailNotVerified() => new(AshlarOidcInvitationRegistrationStatus.EmailNotVerified);

    /// <summary>
    /// Creates an invalid-principal policy result.
    /// </summary>
    /// <returns>The policy result.</returns>
    public static OidcInvitationEmailMatchResult InvalidPrincipal() => new(AshlarOidcInvitationRegistrationStatus.InvalidPrincipal);

    /// <summary>
    /// Creates a failed policy result.
    /// </summary>
    /// <returns>The policy result.</returns>
    public static OidcInvitationEmailMatchResult Failed() => new(AshlarOidcInvitationRegistrationStatus.Failed);
}
