using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Ashlar.OAuth.Providers.Apple;

/// <summary>
/// Provides Apple OpenID Connect registration helpers.
/// </summary>
public static class AppleOidcExtensions
{
    /// <summary>
    /// Adds the Apple OpenID Connect provider preset.
    /// </summary>
    /// <param name="options">The Ashlar OAuth options.</param>
    /// <param name="configure">Additional OpenID Connect handler configuration.</param>
    /// <returns>The options instance.</returns>
    public static AshlarOAuthOptions AddApple(this AshlarOAuthOptions options, Action<OpenIdConnectOptions>? configure)
    {
        return options.AddApple(AppleOidcDefaults.ProviderName, configure);
    }

    /// <summary>
    /// Adds the Apple OpenID Connect provider preset.
    /// </summary>
    /// <param name="options">The Ashlar OAuth options.</param>
    /// <param name="providerName">The Ashlar provider name to register.</param>
    /// <param name="configure">Additional OpenID Connect handler configuration.</param>
    /// <returns>The options instance.</returns>
    public static AshlarOAuthOptions AddApple(
        this AshlarOAuthOptions options,
        string providerName = AppleOidcDefaults.ProviderName,
        Action<OpenIdConnectOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        var normalizedProviderName = AshlarOAuthOptions.NormalizeProviderName(providerName);

        return options.AddOidcProvider(new AshlarOidcProviderOptions(normalizedProviderName, normalizedProviderName, oidcOptions =>
        {
            oidcOptions.Authority = AppleOidcDefaults.Authority;
            oidcOptions.ResponseType = "code";
            oidcOptions.ResponseMode = OpenIdConnectResponseMode.FormPost;
            oidcOptions.Scope.Remove("profile");
            oidcOptions.AddIfMissing("openid");
            oidcOptions.AddIfMissing("email");
            oidcOptions.AddIfMissing("name");
            configure?.Invoke(oidcOptions);
            ConfigureUserNameClaims(oidcOptions);
        }, AshlarOidcProviderKeyMode.Subject, GetClaimsFromUserInfoEndpoint: false));
    }

    private static void ConfigureUserNameClaims(OpenIdConnectOptions options)
    {
        var onTokenValidated = options.Events.OnTokenValidated;
        options.Events.OnTokenValidated = async context =>
        {
            AddUserNameClaims(context);
            if (onTokenValidated != null)
            {
                await onTokenValidated(context);
            }
        };
    }

    private static void AddUserNameClaims(TokenValidatedContext context)
    {
        if (context.Principal?.Identity is not ClaimsIdentity identity)
        {
            return;
        }

        var userJson = context.ProtocolMessage.GetParameter("user");
        if (string.IsNullOrWhiteSpace(userJson))
        {
            return;
        }

        if (!TryReadAppleName(userJson, out var givenName, out var familyName))
        {
            return;
        }

        AddClaimIfMissing(identity, "given_name", givenName);
        AddClaimIfMissing(identity, "family_name", familyName);
        AddClaimIfMissing(identity, "name", CreateDisplayName(givenName, familyName));
    }

    private static bool TryReadAppleName(string userJson, out string? givenName, out string? familyName)
    {
        givenName = null;
        familyName = null;

        try
        {
            using var document = JsonDocument.Parse(userJson);
            if (!document.RootElement.TryGetProperty("name", out var nameElement) || nameElement.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            givenName = ReadTrimmedString(nameElement, "firstName");
            familyName = ReadTrimmedString(nameElement, "lastName");
            return givenName != null || familyName != null;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static string? ReadTrimmedString(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property) || property.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        var value = property.GetString()!.Trim();
        return string.IsNullOrEmpty(value) ? null : value;
    }

    private static string? CreateDisplayName(string? givenName, string? familyName)
    {
        if (givenName == null)
        {
            return familyName;
        }

        return familyName == null ? givenName : string.Concat(givenName, " ", familyName);
    }

    private static void AddClaimIfMissing(ClaimsIdentity identity, string claimType, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value) && !identity.HasClaim(claim => string.Equals(claim.Type, claimType, StringComparison.Ordinal)))
        {
            identity.AddClaim(new Claim(claimType, value));
        }
    }
}
