using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

/// <summary>
/// Represents an authentication assertion, such as a password, a JWT, or a SAML assertion.
/// </summary>
public interface IAuthenticationAssertion
{
    /// <summary>
    /// Gets the provider identity value.
    /// </summary>
    AuthenticationProviderKey ProviderIdentity { get; }
}
