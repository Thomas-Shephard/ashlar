
namespace Ashlar.Identity.Providers.Local;

/// <summary>
/// Represents the local <paramref name="Password" /> assertion data model.
/// </summary>
/// <param name="Password">The password value.</param>
public sealed record LocalPasswordAssertion(string Password) : IAuthenticationAssertion
{
    /// <summary>
    /// Gets or sets the provider identity value.
    /// </summary>
    public AuthenticationProviderKey ProviderIdentity => AuthenticationProviderKey.Local;
}


