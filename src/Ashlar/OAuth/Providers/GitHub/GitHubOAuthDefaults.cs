namespace Ashlar.OAuth.Providers.GitHub;

/// <summary>
/// Provides defaults for GitHub OAuth2 authentication.
/// </summary>
public static class GitHubOAuthDefaults
{
    /// <summary>
    /// The default Ashlar provider name.
    /// </summary>
    public const string ProviderName = "GitHub";

    /// <summary>
    /// The GitHub OAuth authorization endpoint.
    /// </summary>
    public const string AuthorizationEndpoint = "https://github.com/login/oauth/authorize";

    /// <summary>
    /// The GitHub OAuth token endpoint.
    /// </summary>
    public const string TokenEndpoint = "https://github.com/login/oauth/access_token";

    /// <summary>
    /// The GitHub user information endpoint.
    /// </summary>
    public const string UserInformationEndpoint = "https://api.github.com/user";

    /// <summary>
    /// The stable GitHub user id claim type.
    /// </summary>
    public const string IdClaimType = "id";

    /// <summary>
    /// The GitHub login claim type.
    /// </summary>
    public const string LoginClaimType = "login";
}
