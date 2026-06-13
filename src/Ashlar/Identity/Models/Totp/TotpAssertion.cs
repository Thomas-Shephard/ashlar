namespace Ashlar.Identity.Models.Totp;

/// <summary>
/// Carries a user-submitted TOTP code for additional verification.
/// </summary>
public sealed record TotpAssertion : IAuthenticationAssertion
{
    /// <summary>
    /// Creates an assertion for the submitted TOTP code.
    /// </summary>
    /// <param name="code">User-submitted one-time code. Do not log this value.</param>
    /// <param name="providerKey">TOTP provider key to authenticate against, or <see langword="null" /> to use the default TOTP provider.</param>
    public TotpAssertion(string code, AuthenticationProviderKey? providerKey = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(code);
        Code = code;
        ProviderKey = providerKey;
    }

    /// <summary>
    /// User-submitted one-time code. Do not log this value.
    /// </summary>
    public string Code { get; }

    /// <summary>
    /// Gets the TOTP provider key requested by the caller, when one was supplied.
    /// </summary>
    public AuthenticationProviderKey? ProviderKey { get; }

    /// <inheritdoc />
    public AuthenticationProviderKey ProviderIdentity => ProviderKey ?? TotpOptions.DefaultProviderKey;
}
