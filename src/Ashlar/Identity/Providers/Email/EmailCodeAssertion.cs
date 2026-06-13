namespace Ashlar.Identity.Providers.Email;

/// <summary>
/// Carries a user-submitted email sign-in code.
/// </summary>
public sealed record EmailCodeAssertion : IAuthenticationAssertion
{
    /// <summary>
    /// Creates an assertion for the default email-code provider.
    /// </summary>
    /// <param name="code">User-submitted sign-in code. Do not log this value.</param>
    public EmailCodeAssertion(string code)
        : this(code, AuthenticationProviderKey.EmailCode)
    {
    }

    /// <summary>
    /// Creates an assertion for the specified email-code provider.
    /// </summary>
    /// <param name="code">User-submitted sign-in code. Do not log this value.</param>
    /// <param name="providerIdentity">Provider key that should validate the code.</param>
    public EmailCodeAssertion(string code, AuthenticationProviderKey providerIdentity)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(code);

        Code = code;
        ProviderIdentity = providerIdentity;
    }

    /// <summary>
    /// User-submitted sign-in code. Do not log this value.
    /// </summary>
    public string Code { get; }
    /// <summary>
    /// Gets the provider key that should validate the code.
    /// </summary>
    public AuthenticationProviderKey ProviderIdentity { get; }
}
