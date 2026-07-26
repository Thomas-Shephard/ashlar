using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.OAuth;

namespace Ashlar.OAuth.Providers.GitHub;

/// <summary>
/// Provides GitHub OAuth2 registration helpers.
/// </summary>
public static class GitHubOAuthExtensions
{
    /// <summary>
    /// Adds the GitHub OAuth2 provider preset.
    /// </summary>
    /// <param name="options">The Ashlar OAuth options.</param>
    /// <param name="configure">Additional OAuth handler configuration.</param>
    /// <returns>The options instance.</returns>
    public static AshlarOAuthOptions AddGitHub(this AshlarOAuthOptions options, Action<OAuthOptions>? configure)
    {
        return options.AddGitHub(GitHubOAuthDefaults.ProviderName, configure);
    }

    /// <summary>
    /// Adds the GitHub OAuth2 provider preset.
    /// </summary>
    /// <param name="options">The Ashlar OAuth options.</param>
    /// <param name="providerName">The Ashlar provider name to register.</param>
    /// <param name="configure">Additional OAuth handler configuration.</param>
    /// <returns>The options instance.</returns>
    public static AshlarOAuthOptions AddGitHub(
        this AshlarOAuthOptions options,
        string providerName = GitHubOAuthDefaults.ProviderName,
        Action<OAuthOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        var normalizedProviderName = AshlarOAuthOptions.NormalizeProviderName(providerName);

        return options.AddOAuth2Provider(new AshlarOAuth2ProviderOptions(normalizedProviderName, normalizedProviderName, oauthOptions =>
        {
            oauthOptions.AuthorizationEndpoint = GitHubOAuthDefaults.AuthorizationEndpoint;
            oauthOptions.TokenEndpoint = GitHubOAuthDefaults.TokenEndpoint;
            oauthOptions.UserInformationEndpoint = GitHubOAuthDefaults.UserInformationEndpoint;
            oauthOptions.Scope.Clear();
            configure?.Invoke(oauthOptions);
            oauthOptions.UsePkce = true;
            ConfigureUserInformationEndpoint(oauthOptions);
        }));
    }

    private static void ConfigureUserInformationEndpoint(OAuthOptions options)
    {
        var onCreatingTicket = options.Events.OnCreatingTicket;
        options.Events.OnCreatingTicket = async context =>
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
            var version = typeof(GitHubOAuthExtensions).Assembly.GetName().Version?.ToString();
            request.Headers.UserAgent.Add(version == null
                ? new ProductInfoHeaderValue("Ashlar")
                : new ProductInfoHeaderValue("Ashlar", version));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);

            using var response = await context.Backchannel.SendAsync(request, context.HttpContext.RequestAborted);
            if (!response.IsSuccessStatusCode)
            {
                context.Fail($"GitHub user information request failed with status code {(int)response.StatusCode}.");
                return;
            }

            JsonDocument payload;
            try
            {
                await using var stream = await response.Content.ReadAsStreamAsync(context.HttpContext.RequestAborted);
                payload = await JsonDocument.ParseAsync(stream, cancellationToken: context.HttpContext.RequestAborted);
            }
            catch (JsonException exception)
            {
                context.Fail(exception);
                return;
            }

            using (payload)
            {
                AddGitHubClaims(context.Identity, payload.RootElement);
            }

            if (onCreatingTicket != null)
            {
                await onCreatingTicket(context);
            }
        };
    }

    private static void AddGitHubClaims(ClaimsIdentity? identity, JsonElement user)
    {
        if (identity == null)
        {
            return;
        }

        AddClaimIfPresent(identity, GitHubOAuthDefaults.IdClaimType, user, GitHubOAuthDefaults.IdClaimType);
        AddClaimIfPresent(identity, ClaimTypes.NameIdentifier, user, GitHubOAuthDefaults.IdClaimType);
        AddClaimIfPresent(identity, GitHubOAuthDefaults.LoginClaimType, user, GitHubOAuthDefaults.LoginClaimType);
        AddClaimIfPresent(identity, ClaimTypes.Name, user, "name");
        AddClaimIfPresent(identity, ClaimTypes.Email, user, "email");
    }

    private static void AddClaimIfPresent(ClaimsIdentity identity, string claimType, JsonElement user, string propertyName)
    {
        if (identity.HasClaim(claim => string.Equals(claim.Type, claimType, StringComparison.Ordinal))
            || !user.TryGetProperty(propertyName, out var property))
        {
            return;
        }

        var value = property.ValueKind switch
        {
            JsonValueKind.String => property.GetString()!.Trim(),
            JsonValueKind.Number => property.GetRawText(),
            _ => null
        };

        if (!string.IsNullOrWhiteSpace(value))
        {
            identity.AddClaim(new Claim(claimType, value));
        }
    }
}
