namespace Ashlar.Identity.Abstractions.Authentication;

/// <summary>
/// Represents an authentication assertion, such as a password, a JWT, or a SAML assertion.
/// </summary>
public interface IAuthenticationAssertion
{
    /// <summary>
    /// Gets the provider key that should validate this assertion.
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

/// <summary>
/// Represents an authentication assertion that reports whether the authenticator verified the user.
/// Secondary factor verification rejects assertions that report <see langword="false" /> before credential resolution.
/// </summary>
public interface IUserVerifiedAuthenticationAssertion : IAuthenticationAssertion
{
    /// <summary>
    /// Gets a value indicating whether user verification was performed.
    /// </summary>
    bool UserVerified { get; }
}
