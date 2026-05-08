using Ashlar.Identity.Abstractions;

namespace Ashlar.Identity.Models.Totp;

/// <summary>
/// Represents a TOTP authentication assertion.
/// </summary>
public sealed record TotpAssertion(
    string Code,
    string? IpAddress = null,
    AuthenticationProviderKey? ProviderKey = null) : IAuthenticationAssertion
{
    /// <inheritdoc />
    public AuthenticationProviderKey ProviderIdentity => ProviderKey ?? TotpOptions.DefaultProviderKey;
}
