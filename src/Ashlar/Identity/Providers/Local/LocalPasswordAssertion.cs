namespace Ashlar.Identity.Providers.Local;

/// <summary>
/// Carries a plaintext <paramref name="Password" /> for local authentication.
/// </summary>
/// <param name="Password">Plaintext password submitted by the user. Do not log this value.</param>
public sealed record LocalPasswordAssertion(string Password) : IAuthenticationAssertion
{
    /// <summary>
    /// Gets the local password provider key.
    /// </summary>
    public AuthenticationProviderKey ProviderIdentity => AuthenticationProviderKey.Local;
}
