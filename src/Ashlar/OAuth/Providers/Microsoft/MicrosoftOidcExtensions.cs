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
    /// Invitation registration uses standard verified OIDC <c>email</c> matching unless Microsoft email-like claims are explicitly allowed.
    /// </summary>
    /// <param name="options">The Ashlar OAuth options.</param>
    /// <param name="tenantIdOrName">The explicit tenant ID or domain.</param>
    /// <param name="configure">Additional OpenID Connect handler configuration.</param>
    /// <param name="configureInvitationEmailMatch">Optional tenant-specific configuration for trusting Microsoft email-like claims. Claims such as <c>preferred_username</c>, <c>upn</c>, and <c>unique_name</c> can be aliases, guest identifiers, or mutable UPN-like values; opting in reflects tenant policy, not general mailbox verification.</param>
    /// <returns>The options instance.</returns>
    public static AshlarOAuthOptions AddMicrosoft(
        this AshlarOAuthOptions options,
        string tenantIdOrName,
        Action<OpenIdConnectOptions>? configure,
        Action<MicrosoftOidcInvitationEmailMatchOptions>? configureInvitationEmailMatch = null)
    {
        return options.AddMicrosoft(tenantIdOrName, MicrosoftOidcDefaults.ProviderName, configure, configureInvitationEmailMatch);
    }

    /// <summary>
    /// Adds a Microsoft Entra ID OpenID Connect provider preset for an explicit tenant.
    /// Invitation registration uses standard verified OIDC <c>email</c> matching unless Microsoft email-like claims are explicitly allowed.
    /// </summary>
    /// <param name="options">The Ashlar OAuth options.</param>
    /// <param name="tenantIdOrName">The explicit tenant ID or domain.</param>
    /// <param name="providerName">The Ashlar provider name to register.</param>
    /// <param name="configure">Additional OpenID Connect handler configuration.</param>
    /// <param name="configureInvitationEmailMatch">Optional tenant-specific configuration for trusting Microsoft email-like claims. Claims such as <c>preferred_username</c>, <c>upn</c>, and <c>unique_name</c> can be aliases, guest identifiers, or mutable UPN-like values; opting in reflects tenant policy, not general mailbox verification.</param>
    /// <returns>The options instance.</returns>
    public static AshlarOAuthOptions AddMicrosoft(
        this AshlarOAuthOptions options,
        string tenantIdOrName,
        string providerName = MicrosoftOidcDefaults.ProviderName,
        Action<OpenIdConnectOptions>? configure = null,
        Action<MicrosoftOidcInvitationEmailMatchOptions>? configureInvitationEmailMatch = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        var authority = MicrosoftOidcDefaults.BuildAuthority(tenantIdOrName);
        var normalizedProviderName = AshlarOAuthOptions.NormalizeProviderName(providerName);
        var invitationEmailMatchOptions = new MicrosoftOidcInvitationEmailMatchOptions();
        configureInvitationEmailMatch?.Invoke(invitationEmailMatchOptions);
        var allowedEmailLikeClaimTypes = invitationEmailMatchOptions.AllowedEmailLikeClaimTypes.ToArray();
        options.AddInvitationEmailMatchPolicyDecorator(policy => new MicrosoftOidcInvitationEmailMatchPolicy(normalizedProviderName, policy, allowedEmailLikeClaimTypes));

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
        return options.AddMicrosoftProvider(providerName, MicrosoftOidcDefaults.BuildSignInAuthority(MicrosoftOidcDefaults.PersonalAccountsTenant), configure);
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
            });
    }

    private static AshlarOAuthOptions AddMicrosoftProvider(
        this AshlarOAuthOptions options,
        string providerName,
        string authority,
        Action<OpenIdConnectOptions>? configure)
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
        }));
    }

    private static void ConfigureCommonAuthorityIssuerValidator(OpenIdConnectOptions options)
    {
        var issuerValidator = AadIssuerValidator.GetAadIssuerValidator(options.Authority);
        options.TokenValidationParameters.IssuerValidator = issuerValidator.Validate;
    }
}
