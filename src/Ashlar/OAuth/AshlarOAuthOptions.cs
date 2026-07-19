using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication.OAuth;
using System.Security.Claims;

namespace Ashlar.OAuth;

/// <summary>
/// Configures Ashlar OAuth and OpenID Connect sign-in integration.
/// </summary>
public sealed class AshlarOAuthOptions
{
    private readonly Dictionary<string, AshlarOidcProviderOptions> _oidcProviders = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, AshlarOAuth2ProviderOptions> _oauth2Providers = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<Func<IOidcInvitationEmailMatchPolicy, IOidcInvitationEmailMatchPolicy>> _invitationEmailMatchPolicyDecorators = [];
    private static readonly HashSet<string> UnsafeOAuth2ProviderKeyClaimTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "email",
        "email_address",
        "emailaddress",
        "emails",
        "mail",
        "name",
        "display_name",
        "given_name",
        "family_name",
        "nickname",
        "preferred_username",
        "preferredUsername",
        "screen_name",
        "unique_name",
        "username",
        "userPrincipalName",
        "login",
        "upn",
        ClaimTypes.Email,
        ClaimTypes.Name,
        ClaimTypes.Upn
    };

    /// <summary>
    /// Gets or sets the temporary ASP.NET Core sign-in scheme used by remote authentication handlers.
    /// </summary>
    public string ExternalSignInScheme { get; set; } = "Ashlar.OAuth.External";

    /// <summary>
    /// Gets the configured OpenID Connect providers keyed by normalized provider name.
    /// </summary>
    public IReadOnlyDictionary<string, AshlarOidcProviderOptions> OidcProviders => _oidcProviders;

    /// <summary>
    /// Gets the configured non-OIDC OAuth2 providers keyed by normalized provider name.
    /// </summary>
    public IReadOnlyDictionary<string, AshlarOAuth2ProviderOptions> OAuth2Providers => _oauth2Providers;

    internal IReadOnlyList<Func<IOidcInvitationEmailMatchPolicy, IOidcInvitationEmailMatchPolicy>> InvitationEmailMatchPolicyDecorators => _invitationEmailMatchPolicyDecorators;

    /// <summary>
    /// Adds a generic OpenID Connect provider using issuer-qualified subject provider keys.
    /// </summary>
    /// <param name="providerName">The Ashlar provider name.</param>
    /// <param name="configure">The OpenID Connect handler configuration callback.</param>
    /// <param name="getClaimsFromUserInfoEndpoint">Whether the handler should request claims from the provider user-info endpoint.</param>
    /// <returns>The options instance.</returns>
    public AshlarOAuthOptions AddOidcProvider(
        string providerName,
        Action<OpenIdConnectOptions> configure,
        bool getClaimsFromUserInfoEndpoint = true)
    {
        var normalizedName = NormalizeProviderName(providerName);
        ArgumentNullException.ThrowIfNull(configure);
        return AddOidcProvider(new AshlarOidcProviderOptions(normalizedName, normalizedName, configure, getClaimsFromUserInfoEndpoint));
    }

    /// <summary>
    /// Adds a generic non-OIDC OAuth2 provider using the provider's <c>id</c> claim as the stable Ashlar provider key.
    /// </summary>
    /// <param name="providerName">The Ashlar provider name.</param>
    /// <param name="configure">The OAuth handler configuration callback.</param>
    /// <returns>The options instance.</returns>
    public AshlarOAuthOptions AddOAuth2Provider(string providerName, Action<OAuthOptions> configure)
    {
        return AddOAuth2Provider(providerName, "id", configure);
    }

    /// <summary>
    /// Adds a generic non-OIDC OAuth2 provider using a stable immutable provider user id claim as the Ashlar provider key.
    /// </summary>
    /// <param name="providerName">The Ashlar provider name.</param>
    /// <param name="providerKeyClaimType">The validated principal claim type that contains the stable immutable provider user id. Email, username, login, and display-name claims are rejected because they can be mutable or non-unique.</param>
    /// <param name="configure">The OAuth handler configuration callback.</param>
    /// <returns>The options instance.</returns>
    public AshlarOAuthOptions AddOAuth2Provider(string providerName, string providerKeyClaimType, Action<OAuthOptions> configure)
    {
        var normalizedName = NormalizeProviderName(providerName);
        var normalizedProviderKeyClaimType = NormalizeProviderKeyClaimType(providerKeyClaimType);
        ValidateOAuth2ProviderKeyClaimType(normalizedProviderKeyClaimType, allowUnsafeProviderKeyClaimType: false);
        ArgumentNullException.ThrowIfNull(configure);

        return AddOAuth2Provider(new AshlarOAuth2ProviderOptions(normalizedName, normalizedName, configure, normalizedProviderKeyClaimType));
    }

    /// <summary>
    /// Adds a generic non-OIDC OAuth2 provider while explicitly accepting responsibility for an otherwise unsafe provider-key claim type.
    /// </summary>
    /// <param name="providerName">The Ashlar provider name.</param>
    /// <param name="providerKeyClaimType">The validated principal claim type that the caller has independently confirmed is a stable immutable provider user id.</param>
    /// <param name="configure">The OAuth handler configuration callback.</param>
    /// <returns>The options instance.</returns>
    public AshlarOAuthOptions AddOAuth2ProviderWithUnsafeProviderKeyClaimType(string providerName, string providerKeyClaimType, Action<OAuthOptions> configure)
    {
        var normalizedName = NormalizeProviderName(providerName);
        var normalizedProviderKeyClaimType = NormalizeProviderKeyClaimType(providerKeyClaimType);
        ArgumentNullException.ThrowIfNull(configure);

        return AddOAuth2Provider(new AshlarOAuth2ProviderOptions(
            normalizedName,
            normalizedName,
            configure,
            normalizedProviderKeyClaimType,
            AllowUnsafeProviderKeyClaimType: true));
    }

    internal AshlarOAuthOptions AddOidcProvider(AshlarOidcProviderOptions provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        var normalizedName = NormalizeProviderName(provider.ProviderName);
        if (_oauth2Providers.ContainsKey(normalizedName))
        {
            throw new ArgumentException($"A provider named '{normalizedName}' is already registered.", nameof(provider));
        }

        var normalizedProvider = provider with { ProviderName = normalizedName };
        if (!_oidcProviders.TryAdd(normalizedName, normalizedProvider))
        {
            throw new ArgumentException($"An OIDC provider named '{normalizedName}' is already registered.", nameof(provider));
        }

        return this;
    }

    internal AshlarOAuthOptions AddOAuth2Provider(AshlarOAuth2ProviderOptions provider)
    {
        ArgumentNullException.ThrowIfNull(provider);

        var normalizedName = NormalizeProviderName(provider.ProviderName);
        var normalizedSchemeName = NormalizeProviderName(provider.SchemeName);
        var normalizedProviderKeyClaimType = NormalizeProviderKeyClaimType(provider.ProviderKeyClaimType);
        ValidateOAuth2ProviderKeyClaimType(normalizedProviderKeyClaimType, provider.AllowUnsafeProviderKeyClaimType);
        if (_oidcProviders.ContainsKey(normalizedName))
        {
            throw new ArgumentException($"A provider named '{normalizedName}' is already registered.", nameof(provider));
        }

        var normalizedProvider = provider with
        {
            ProviderName = normalizedName,
            SchemeName = normalizedSchemeName,
            ProviderKeyClaimType = normalizedProviderKeyClaimType
        };
        if (!_oauth2Providers.TryAdd(normalizedName, normalizedProvider))
        {
            throw new ArgumentException($"An OAuth2 provider named '{normalizedName}' is already registered.", nameof(provider));
        }

        return this;
    }

    internal static string NormalizeProviderName(string providerName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerName);
        return providerName.Trim();
    }

    internal static string NormalizeProviderKeyClaimType(string providerKeyClaimType)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerKeyClaimType);
        return providerKeyClaimType.Trim();
    }

    internal static void ValidateOAuth2ProviderKeyClaimType(string providerKeyClaimType, bool allowUnsafeProviderKeyClaimType)
    {
        var normalizedProviderKeyClaimType = NormalizeProviderKeyClaimType(providerKeyClaimType);
        if (!allowUnsafeProviderKeyClaimType && UnsafeOAuth2ProviderKeyClaimTypes.Contains(normalizedProviderKeyClaimType))
        {
            throw new ArgumentException(
                "The OAuth2 provider key claim type must identify a stable immutable provider user id. Do not use email, username, login, or display-name claims as provider keys.",
                nameof(providerKeyClaimType));
        }
    }

    internal void AddInvitationEmailMatchPolicyDecorator(Func<IOidcInvitationEmailMatchPolicy, IOidcInvitationEmailMatchPolicy> decorator)
    {
        ArgumentNullException.ThrowIfNull(decorator);
        _invitationEmailMatchPolicyDecorators.Add(decorator);
    }
}

/// <summary>
/// Describes a configured Ashlar OpenID Connect provider.
/// </summary>
/// <param name="ProviderName">The normalized Ashlar provider name.</param>
/// <param name="SchemeName">The ASP.NET Core authentication scheme name.</param>
/// <param name="Configure">The OpenID Connect handler configuration callback.</param>
/// <param name="GetClaimsFromUserInfoEndpoint">Whether the handler should request claims from the provider user-info endpoint.</param>
public sealed record AshlarOidcProviderOptions(
    string ProviderName,
    string SchemeName,
    Action<OpenIdConnectOptions> Configure,
    bool GetClaimsFromUserInfoEndpoint = true);

/// <summary>
/// Describes a configured Ashlar non-OIDC OAuth2 provider.
/// </summary>
/// <param name="ProviderName">The normalized Ashlar provider name.</param>
/// <param name="SchemeName">The ASP.NET Core authentication scheme name.</param>
/// <param name="Configure">The OAuth handler configuration callback.</param>
/// <param name="ProviderKeyClaimType">The validated principal claim type that contains the stable immutable provider user id. Use provider-assigned subject identifiers such as <c>id</c>, <c>sub</c>, <c>uid</c>, or <c>user_id</c>; do not use email, username, login, or display-name claims.</param>
/// <param name="AllowUnsafeProviderKeyClaimType">Whether the caller explicitly accepts responsibility for using a claim type that Ashlar normally rejects as mutable or non-unique.</param>
public sealed record AshlarOAuth2ProviderOptions(
    string ProviderName,
    string SchemeName,
    Action<OAuthOptions> Configure,
    string ProviderKeyClaimType = "id",
    bool AllowUnsafeProviderKeyClaimType = false);
