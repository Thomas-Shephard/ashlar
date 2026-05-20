namespace Ashlar.Identity.Abstractions.Authentication;

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

/// <summary>
/// Represents an authentication assertion that can expose the stored credential lookup key it used.
/// </summary>
public interface ICredentialKeyAuthenticationAssertion : IAuthenticationAssertion
{
    /// <summary>
    /// Gets the provider credential key.
    /// </summary>
    string CredentialKey { get; }
}
