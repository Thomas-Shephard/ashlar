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
    /// <param name="code">The TOTP code.</param>
    /// <param name="ipAddress">Optional IP address.</param>
    /// <param name="providerKey">Optional provider key.</param>
    public TotpAssertion(string code, string? ipAddress = null, AuthenticationProviderKey? providerKey = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(code);
        Code = code;
        IpAddress = ipAddress;
        ProviderKey = providerKey;
    }

    /// <summary>
    /// Gets the TOTP code.
    /// </summary>
    public string Code { get; }

    /// <summary>
    /// Gets the IP address.
    /// </summary>
    public string? IpAddress { get; }

    /// <summary>
    /// Gets the provider key.
    /// </summary>
    public AuthenticationProviderKey? ProviderKey { get; }

    /// <inheritdoc />
    public AuthenticationProviderKey ProviderIdentity => ProviderKey ?? TotpOptions.DefaultProviderKey;
}
