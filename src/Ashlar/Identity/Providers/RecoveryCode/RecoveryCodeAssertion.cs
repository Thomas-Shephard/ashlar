namespace Ashlar.Identity.Providers.RecoveryCode;

/// <summary>
/// Represents an authentication assertion using a recovery code.
/// </summary>
public sealed record RecoveryCodeAssertion : IAuthenticationAssertion
{
    /// <summary>
    /// Creates an assertion for a submitted recovery code.
    /// </summary>
    /// <param name="code">User-submitted recovery code. Do not log this value.</param>
    /// <param name="providerIdentity">Recovery-code provider key to authenticate against, or <see langword="null" /> to use the default recovery-code provider.</param>
    public RecoveryCodeAssertion(string code, AuthenticationProviderKey? providerIdentity = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(code);
        Code = code;
        ProviderIdentity = providerIdentity ?? new AuthenticationProviderKey(ProviderType.RecoveryCode, "RecoveryCode");
    }

    /// <summary>
    /// User-submitted recovery code. Do not log this value.
    /// </summary>
    public string Code { get; }

    /// <inheritdoc />
    public AuthenticationProviderKey ProviderIdentity { get; }
}
