namespace Ashlar.OAuth.Providers.Microsoft;

/// <summary>
/// Invitation email policy for Microsoft identity platform providers.
/// </summary>
public sealed class MicrosoftOidcInvitationEmailMatchPolicy : IOidcInvitationEmailMatchPolicy
{
    private static readonly string[] CandidateEmailClaimTypes =
    [
        "email",
        "preferred_username",
        "upn",
        "unique_name"
    ];

    private readonly string _providerName;
    private readonly IOidcInvitationEmailMatchPolicy _fallbackPolicy;

    /// <summary>
    /// Initializes a new instance of the Microsoft invitation email policy.
    /// </summary>
    /// <param name="providerName">The configured Microsoft provider name.</param>
    /// <param name="fallbackPolicy">The fallback policy for non-Microsoft providers.</param>
    public MicrosoftOidcInvitationEmailMatchPolicy(string providerName, IOidcInvitationEmailMatchPolicy fallbackPolicy)
    {
        _providerName = AshlarOAuthOptions.NormalizeProviderName(providerName);
        _fallbackPolicy = fallbackPolicy ?? throw new ArgumentNullException(nameof(fallbackPolicy));
    }

    /// <inheritdoc />
    public OidcInvitationEmailMatchResult Validate(OidcInvitationEmailMatchContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!string.Equals(_providerName, context.ProviderName, StringComparison.OrdinalIgnoreCase))
        {
            return _fallbackPolicy.Validate(context);
        }

        if (CandidateEmailClaimTypes
            .SelectMany(context.Principal.FindAll)
            .Any(claim => string.Equals(claim.Value.Trim(), context.Invitation.Email.Trim(), StringComparison.OrdinalIgnoreCase)))
        {
            return OidcInvitationEmailMatchResult.Success();
        }

        return HasAnyCandidateEmail(context.Principal)
            ? OidcInvitationEmailMatchResult.EmailMismatch()
            : OidcInvitationEmailMatchResult.EmailNotVerified();
    }

    private static bool HasAnyCandidateEmail(System.Security.Claims.ClaimsPrincipal principal)
    {
        return CandidateEmailClaimTypes.Any(claimType => principal.FindAll(claimType).Any(claim => !string.IsNullOrWhiteSpace(claim.Value)));
    }
}
