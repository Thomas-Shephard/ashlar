using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace Ashlar.OAuth;

/// <summary>
/// Configures Ashlar OAuth and OpenID Connect sign-in integration.
/// </summary>
public sealed class AshlarOAuthOptions
{
    private readonly Dictionary<string, AshlarOidcProviderOptions> _oidcProviders = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Gets or sets the temporary ASP.NET Core sign-in scheme used by remote authentication handlers.
    /// </summary>
    public string ExternalSignInScheme { get; set; } = "Ashlar.OAuth.External";

    /// <summary>
    /// Gets the configured OpenID Connect providers keyed by normalized provider name.
    /// </summary>
    public IReadOnlyDictionary<string, AshlarOidcProviderOptions> OidcProviders => _oidcProviders;

    /// <summary>
    /// Adds a generic OpenID Connect provider.
    /// </summary>
    /// <param name="providerName">The Ashlar provider name.</param>
    /// <param name="configure">The OpenID Connect handler configuration callback.</param>
    /// <returns>The options instance.</returns>
    public AshlarOAuthOptions AddOidcProvider(string providerName, Action<OpenIdConnectOptions> configure)
    {
        var normalizedName = NormalizeProviderName(providerName);
        ArgumentNullException.ThrowIfNull(configure);

        if (!_oidcProviders.TryAdd(normalizedName, new AshlarOidcProviderOptions(normalizedName, normalizedName, configure)))
        {
            throw new ArgumentException($"An OIDC provider named '{normalizedName}' is already registered.", nameof(providerName));
        }

        return this;
    }

    internal static string NormalizeProviderName(string providerName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerName);
        return providerName.Trim();
    }
}

/// <summary>
/// Describes a configured Ashlar OpenID Connect provider.
/// </summary>
/// <param name="ProviderName">The normalized Ashlar provider name.</param>
/// <param name="SchemeName">The ASP.NET Core authentication scheme name.</param>
/// <param name="Configure">The OpenID Connect handler configuration callback.</param>
public sealed record AshlarOidcProviderOptions(
    string ProviderName,
    string SchemeName,
    Action<OpenIdConnectOptions> Configure);
