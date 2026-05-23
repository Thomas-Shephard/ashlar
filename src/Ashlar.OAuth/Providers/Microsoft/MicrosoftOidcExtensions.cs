using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Validators;

namespace Ashlar.OAuth.Providers.Microsoft;

/// <summary>
/// Provides Microsoft Entra ID OpenID Connect registration helpers.
/// </summary>
public static class MicrosoftOidcExtensions
{
    /// <summary>
    /// Adds a Microsoft Entra ID OpenID Connect provider preset for an explicit tenant.
    /// </summary>
    /// <param name="options">The Ashlar OAuth options.</param>
    /// <param name="tenantIdOrName">The explicit tenant ID or domain.</param>
    /// <param name="configure">Additional OpenID Connect handler configuration.</param>
    /// <returns>The options instance.</returns>
    public static AshlarOAuthOptions AddMicrosoft(
        this AshlarOAuthOptions options,
        string tenantIdOrName,
        Action<OpenIdConnectOptions>? configure)
    {
        return options.AddMicrosoft(tenantIdOrName, MicrosoftOidcDefaults.ProviderName, configure);
    }

    /// <summary>
    /// Adds a Microsoft Entra ID OpenID Connect provider preset for an explicit tenant.
    /// </summary>
    /// <param name="options">The Ashlar OAuth options.</param>
    /// <param name="tenantIdOrName">The explicit tenant ID or domain.</param>
    /// <param name="providerName">The Ashlar provider name to register.</param>
    /// <param name="configure">Additional OpenID Connect handler configuration.</param>
    /// <returns>The options instance.</returns>
    public static AshlarOAuthOptions AddMicrosoft(
        this AshlarOAuthOptions options,
        string tenantIdOrName,
        string providerName = MicrosoftOidcDefaults.ProviderName,
        Action<OpenIdConnectOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        var authority = MicrosoftOidcDefaults.BuildAuthority(tenantIdOrName);
        var normalizedProviderName = AshlarOAuthOptions.NormalizeProviderName(providerName);
        options.AddInvitationEmailMatchPolicyDecorator(policy => new MicrosoftOidcInvitationEmailMatchPolicy(normalizedProviderName, policy));

        return options.AddMicrosoftProvider(providerName, authority, configure);
    }

    /// <summary>
    /// Adds a Microsoft identity platform OpenID Connect provider preset for personal Microsoft accounts.
    /// </summary>
    /// <param name="options">The Ashlar OAuth options.</param>
    /// <param name="providerName">The Ashlar provider name to register.</param>
    /// <param name="configure">Additional OpenID Connect handler configuration.</param>
    /// <returns>The options instance.</returns>
    public static AshlarOAuthOptions AddMicrosoftPersonalAccounts(
        this AshlarOAuthOptions options,
        string providerName = "MicrosoftPersonal",
        Action<OpenIdConnectOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        return options.AddMicrosoftProvider(providerName, MicrosoftOidcDefaults.BuildSignInAuthority(MicrosoftOidcDefaults.PersonalAccountsTenant), configure, AshlarOidcProviderKeyMode.IssuerAndSubject);
    }

    /// <summary>
    /// Adds a Microsoft identity platform OpenID Connect provider preset for work, school, and personal Microsoft accounts.
    /// </summary>
    /// <param name="options">The Ashlar OAuth options.</param>
    /// <param name="providerName">The Ashlar provider name to register.</param>
    /// <param name="configure">Additional OpenID Connect handler configuration.</param>
    /// <returns>The options instance.</returns>
    public static AshlarOAuthOptions AddMicrosoftAnyAccount(
        this AshlarOAuthOptions options,
        string providerName = "MicrosoftAny",
        Action<OpenIdConnectOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        return options.AddMicrosoftProvider(
            providerName,
            MicrosoftOidcDefaults.BuildSignInAuthority(MicrosoftOidcDefaults.AnyAccountTenant),
            oidcOptions =>
            {
                configure?.Invoke(oidcOptions);
                ConfigureCommonAuthorityIssuerValidator(oidcOptions);
            },
            AshlarOidcProviderKeyMode.IssuerAndSubject);
    }

    private static AshlarOAuthOptions AddMicrosoftProvider(
        this AshlarOAuthOptions options,
        string providerName,
        string authority,
        Action<OpenIdConnectOptions>? configure,
        AshlarOidcProviderKeyMode providerKeyMode = AshlarOidcProviderKeyMode.Subject)
    {
        return options.AddMicrosoftProviderCore(providerName, authority, configure, providerKeyMode);
    }

    private static AshlarOAuthOptions AddMicrosoftProviderCore(
        this AshlarOAuthOptions options,
        string providerName,
        string authority,
        Action<OpenIdConnectOptions>? configure,
        AshlarOidcProviderKeyMode providerKeyMode)
    {
        var normalizedProviderName = AshlarOAuthOptions.NormalizeProviderName(providerName);
        return options.AddOidcProvider(new AshlarOidcProviderOptions(normalizedProviderName, normalizedProviderName, oidcOptions =>
        {
            oidcOptions.Authority = authority;
            oidcOptions.ResponseType = "code";
            oidcOptions.AddIfMissing("openid");
            oidcOptions.AddIfMissing("profile");
            oidcOptions.AddIfMissing("email");
            configure?.Invoke(oidcOptions);
        }, providerKeyMode));
    }

    private static void ConfigureCommonAuthorityIssuerValidator(OpenIdConnectOptions options)
    {
        var issuerValidator = AadIssuerValidator.GetAadIssuerValidator(options.Authority);
        options.TokenValidationParameters.IssuerValidator = issuerValidator.Validate;
    }
}
