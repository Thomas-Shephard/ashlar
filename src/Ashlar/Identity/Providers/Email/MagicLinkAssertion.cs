
namespace Ashlar.Identity.Providers.Email;

/// <summary>
/// Represents the magic link assertion data model.
/// </summary>
public sealed record MagicLinkAssertion : IAuthenticationAssertion
{
    /// <summary>
    /// Gets or sets the token value.
    /// </summary>
    public string Token { get; }
    /// <summary>
    /// Gets or sets the provider identity value.
    /// </summary>
    public AuthenticationProviderKey ProviderIdentity { get; } = AuthenticationProviderKey.MagicLink;

    /// <summary>
    /// Initializes a new instance of the magic link assertion class.
    /// </summary>
    /// <param name="token">The token value.</param>
    public MagicLinkAssertion(string token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        Token = token;
    }
}
