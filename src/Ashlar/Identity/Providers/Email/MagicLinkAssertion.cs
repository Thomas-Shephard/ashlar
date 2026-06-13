namespace Ashlar.Identity.Providers.Email;

/// <summary>
/// Carries a user-submitted magic-link token.
/// </summary>
public sealed record MagicLinkAssertion : IAuthenticationAssertion
{
    /// <summary>
    /// Raw magic-link token submitted by the user. Do not log or persist this value.
    /// </summary>
    public string Token { get; }
    /// <summary>
    /// Gets the provider key that should validate the token.
    /// </summary>
    public AuthenticationProviderKey ProviderIdentity { get; } = AuthenticationProviderKey.MagicLink;

    /// <summary>
    /// Creates an assertion for a magic-link token.
    /// </summary>
    /// <param name="token">Raw token from the magic link. Do not log or persist this value.</param>
    public MagicLinkAssertion(string token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        Token = token;
    }
}
