
namespace Ashlar.Identity.Providers.RecoveryCode;

/// <summary>
/// Represents an authentication assertion using a recovery code.
/// </summary>
public sealed record RecoveryCodeAssertion : IAuthenticationAssertion
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RecoveryCodeAssertion"/> class.
    /// </summary>
    /// <param name="code">The code value.</param>
    /// <param name="providerIdentity">The provider identity value.</param>
    public RecoveryCodeAssertion(string code, AuthenticationProviderKey? providerIdentity = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(code);
        Code = code;
        ProviderIdentity = providerIdentity ?? new AuthenticationProviderKey(ProviderType.RecoveryCode, "RecoveryCode");
    }

    /// <summary>
    /// Gets the recovery code.
    /// </summary>
    public string Code { get; }

    /// <inheritdoc />
    public AuthenticationProviderKey ProviderIdentity { get; }
}
