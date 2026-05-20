
namespace Ashlar.Identity.Providers.Email;

/// <summary>
/// Represents the email code assertion data model.
/// </summary>
public sealed record EmailCodeAssertion : IAuthenticationAssertion
{
    /// <summary>
    /// Initializes a new instance of the email code assertion class.
    /// </summary>
    /// <param name="code">The code value.</param>
    public EmailCodeAssertion(string code)
        : this(code, AuthenticationProviderKey.EmailCode)
    {
    }

    /// <summary>
    /// Initializes a new instance of the email code assertion class.
    /// </summary>
    /// <param name="code">The code value.</param>
    /// <param name="providerIdentity">The provider identity value.</param>
    public EmailCodeAssertion(string code, AuthenticationProviderKey providerIdentity)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(code);

        Code = code;
        ProviderIdentity = providerIdentity;
    }

    /// <summary>
    /// Gets or sets the code value.
    /// </summary>
    public string Code { get; }
    /// <summary>
    /// Gets or sets the provider identity value.
    /// </summary>
    public AuthenticationProviderKey ProviderIdentity { get; }
}


