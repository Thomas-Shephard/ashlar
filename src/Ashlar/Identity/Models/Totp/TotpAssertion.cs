using Ashlar.Identity.Abstractions;

namespace Ashlar.Identity.Models.Totp;

/// <summary>
/// Represents a TOTP authentication assertion.
/// </summary>
public sealed record TotpAssertion : IAuthenticationAssertion
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TotpAssertion"/> class.
    /// </summary>
    /// <param name="code">The code value.</param>
    /// <param name="providerKey">The provider key value.</param>
    public TotpAssertion(string code, AuthenticationProviderKey? providerKey = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(code);
        Code = code;
        ProviderKey = providerKey;
    }

    /// <summary>
    /// Gets the TOTP code.
    /// </summary>
    public string Code { get; }

    /// <summary>
    /// Gets the provider key.
    /// </summary>
    public AuthenticationProviderKey? ProviderKey { get; }

    /// <inheritdoc />
    public AuthenticationProviderKey ProviderIdentity => ProviderKey ?? TotpOptions.DefaultProviderKey;
}
