using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;

namespace Ashlar.Identity;

/// <summary>
/// Represents an authentication assertion using a recovery code.
/// </summary>
public sealed record RecoveryCodeAssertion : IAuthenticationAssertion
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RecoveryCodeAssertion"/> class.
    /// </summary>
    /// <param name="code">The recovery code.</param>
    /// <param name="providerIdentity">The provider identity. Defaults to <see cref="ProviderType.RecoveryCode"/>.</param>
    /// <param name="ipAddress">Optional IP address for rate limiting.</param>
    public RecoveryCodeAssertion(string code, AuthenticationProviderKey? providerIdentity = null, string? ipAddress = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(code);
        Code = code;
        ProviderIdentity = providerIdentity ?? new AuthenticationProviderKey(ProviderType.RecoveryCode, "RecoveryCode");
        IpAddress = ipAddress;
    }

    /// <summary>
    /// Gets the recovery code.
    /// </summary>
    public string Code { get; }

    /// <summary>
    /// Gets the IP address.
    /// </summary>
    public string? IpAddress { get; }

    /// <inheritdoc />
    public AuthenticationProviderKey ProviderIdentity { get; }
}
