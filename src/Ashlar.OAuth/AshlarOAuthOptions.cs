using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace Ashlar.OAuth;

/// <summary>
/// Configures Ashlar OAuth and OpenID Connect sign-in integration.
/// </summary>
public sealed class AshlarOAuthOptions
{
    private readonly Dictionary<string, AshlarOidcProviderOptions> _oidcProviders = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<Func<IOidcInvitationEmailMatchPolicy, IOidcInvitationEmailMatchPolicy>> _invitationEmailMatchPolicyDecorators = [];

    /// <summary>
    /// Gets or sets the temporary ASP.NET Core sign-in scheme used by remote authentication handlers.
    /// </summary>
    public string ExternalSignInScheme { get; set; } = "Ashlar.OAuth.External";

    /// <summary>
    /// Gets the configured OpenID Connect providers keyed by normalized provider name.
    /// </summary>
    public IReadOnlyDictionary<string, AshlarOidcProviderOptions> OidcProviders => _oidcProviders;

    internal IReadOnlyList<Func<IOidcInvitationEmailMatchPolicy, IOidcInvitationEmailMatchPolicy>> InvitationEmailMatchPolicyDecorators => _invitationEmailMatchPolicyDecorators;

    /// <summary>
    /// Adds a generic OpenID Connect provider.
    /// </summary>
    /// <param name="providerName">The Ashlar provider name.</param>
    /// <param name="configure">The OpenID Connect handler configuration callback.</param>
    /// <returns>The options instance.</returns>
    public AshlarOAuthOptions AddOidcProvider(string providerName, Action<OpenIdConnectOptions> configure)
    {
        return AddOidcProvider(providerName, AshlarOidcProviderKeyMode.Subject, configure);
    }

    /// <summary>
    /// Adds a generic OpenID Connect provider.
    /// </summary>
    /// <param name="providerName">The Ashlar provider name.</param>
    /// <param name="providerKeyMode">How Ashlar composes the stable provider key from validated OIDC claims.</param>
    /// <param name="configure">The OpenID Connect handler configuration callback.</param>
    /// <returns>The options instance.</returns>
    public AshlarOAuthOptions AddOidcProvider(string providerName, AshlarOidcProviderKeyMode providerKeyMode, Action<OpenIdConnectOptions> configure)
    {
        var normalizedName = NormalizeProviderName(providerName);
        ArgumentNullException.ThrowIfNull(configure);
        ValidateProviderKeyMode(providerKeyMode);

        return AddOidcProvider(new AshlarOidcProviderOptions(normalizedName, normalizedName, configure, providerKeyMode));
    }

    internal AshlarOAuthOptions AddOidcProvider(AshlarOidcProviderOptions provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ValidateProviderKeyMode(provider.ProviderKeyMode);

        var normalizedName = NormalizeProviderName(provider.ProviderName);
        var normalizedProvider = provider with { ProviderName = normalizedName };
        if (!_oidcProviders.TryAdd(normalizedName, normalizedProvider))
        {
            throw new ArgumentException($"An OIDC provider named '{normalizedName}' is already registered.", nameof(provider));
        }

        return this;
    }

    internal static string NormalizeProviderName(string providerName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerName);
        return providerName.Trim();
    }

    private static void ValidateProviderKeyMode(AshlarOidcProviderKeyMode providerKeyMode)
    {
        if (!Enum.IsDefined(providerKeyMode))
        {
            throw new ArgumentOutOfRangeException(nameof(providerKeyMode), providerKeyMode, "The OpenID Connect provider key mode is not supported.");
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
/// <param name="ProviderKeyMode">How Ashlar composes the stable provider key from validated OIDC claims.</param>
public sealed record AshlarOidcProviderOptions(
    string ProviderName,
    string SchemeName,
    Action<OpenIdConnectOptions> Configure,
    AshlarOidcProviderKeyMode ProviderKeyMode = AshlarOidcProviderKeyMode.Subject);

/// <summary>
/// Defines how an OpenID Connect provider key is composed from validated claims.
/// </summary>
public enum AshlarOidcProviderKeyMode
{
    /// <summary>
    /// Uses the OIDC subject claim as the provider key.
    /// </summary>
    Subject = 0,

    /// <summary>
    /// Uses the OIDC issuer and subject claims as the provider key.
    /// </summary>
    IssuerAndSubject = 1
}
