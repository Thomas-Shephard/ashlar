namespace Ashlar.OAuth.Providers.Microsoft;

/// <summary>
/// Configures tenant-specific Microsoft invitation email matching beyond standard verified OIDC email claims.
/// </summary>
public sealed class MicrosoftOidcInvitationEmailMatchOptions
{
    /// <summary>
    /// Gets the Microsoft claim types that may match an invitation email when standard verified <c>email</c> is unavailable.
    /// Microsoft claims such as <c>preferred_username</c>, <c>upn</c>, and <c>unique_name</c> can reflect aliases,
    /// guest-user identifiers, or mutable tenant-specific usernames, and they do not generally prove mailbox control.
    /// Add claim types only when the deployment's Microsoft tenant policies make that claim authoritative for the
    /// invited mailbox; the default is empty.
    /// </summary>
    public ISet<string> AllowedEmailLikeClaimTypes { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
}

/// <summary>
/// Invitation email policy for Microsoft identity platform providers.
/// </summary>
public sealed class MicrosoftOidcInvitationEmailMatchPolicy : IOidcInvitationEmailMatchPolicy
{
    private readonly string _providerName;
    private readonly IOidcInvitationEmailMatchPolicy _fallbackPolicy;
    private readonly string[] _allowedEmailLikeClaimTypes;

    /// <summary>
    /// Initializes a new instance of the Microsoft invitation email policy.
    /// </summary>
    /// <param name="providerName">The configured Microsoft provider name.</param>
    /// <param name="fallbackPolicy">The fallback policy for non-Microsoft providers.</param>
    /// <param name="allowedEmailLikeClaimTypes">Microsoft claim types the deployment explicitly trusts for invitation matching when standard verified <c>email</c> is unavailable. Leave empty unless tenant policy makes these claims authoritative for the invited mailbox.</param>
    public MicrosoftOidcInvitationEmailMatchPolicy(
        string providerName,
        IOidcInvitationEmailMatchPolicy fallbackPolicy,
        IEnumerable<string>? allowedEmailLikeClaimTypes = null)
    {
        _providerName = AshlarOAuthOptions.NormalizeProviderName(providerName);
        _fallbackPolicy = fallbackPolicy ?? throw new ArgumentNullException(nameof(fallbackPolicy));
        _allowedEmailLikeClaimTypes = NormalizeClaimTypes(allowedEmailLikeClaimTypes);
    }

    /// <inheritdoc />
    public OidcInvitationEmailMatchResult Validate(OidcInvitationEmailMatchContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!string.Equals(_providerName, context.ProviderName, StringComparison.OrdinalIgnoreCase))
        {
            return _fallbackPolicy.Validate(context);
        }

        var fallbackResult = _fallbackPolicy.Validate(context);
        if (fallbackResult.Succeeded
            || fallbackResult.Status != AshlarOidcInvitationRegistrationStatus.EmailNotVerified
            || _allowedEmailLikeClaimTypes.Length == 0)
        {
            return fallbackResult;
        }

        if (_allowedEmailLikeClaimTypes
            .SelectMany(context.Principal.FindAll)
            .Any(claim => string.Equals(claim.Value.Trim(), context.Invitation.Email.Trim(), StringComparison.OrdinalIgnoreCase)))
        {
            return OidcInvitationEmailMatchResult.Success();
        }

        return HasAnyAllowedEmailLikeClaim(context.Principal)
            ? OidcInvitationEmailMatchResult.EmailMismatch()
            : fallbackResult;
    }

    private static string[] NormalizeClaimTypes(IEnumerable<string>? claimTypes)
    {
        return claimTypes?
            .Select(claimType =>
            {
                ArgumentException.ThrowIfNullOrWhiteSpace(claimType);
                return claimType.Trim();
            })
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray() ?? [];
    }

    private bool HasAnyAllowedEmailLikeClaim(System.Security.Claims.ClaimsPrincipal principal)
    {
        return _allowedEmailLikeClaimTypes.Any(claimType => principal.FindAll(claimType).Any(claim => !string.IsNullOrWhiteSpace(claim.Value)));
    }
}
