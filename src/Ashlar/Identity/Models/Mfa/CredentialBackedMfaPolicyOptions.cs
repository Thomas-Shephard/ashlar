namespace Ashlar.Identity.Models.Mfa;

/// <summary>
/// Configures an MFA policy that requires factors when qualifying user credentials exist.
/// </summary>
public sealed class CredentialBackedMfaPolicyOptions
{
    /// <summary>
    /// Credential providers that cause this policy to require MFA when present.
    /// </summary>
    public IList<AuthenticationProviderKey> CredentialProviderKeys { get; } = [];

    /// <summary>
    /// Factor families required when a qualifying credential exists.
    /// </summary>
    public IList<string> RequiredFactors { get; } = [];

    /// <summary>
    /// Validates credential-backed MFA policy options.
    /// </summary>
    /// <param name="options">The options instance to validate.</param>
    /// <returns><see langword="true" /> when at least one provider key and factor are configured.</returns>
    public static bool Validate(CredentialBackedMfaPolicyOptions? options)
    {
        return options is not null
            && options.RequiredFactors.Count > 0
            && options.RequiredFactors.All(factor => !string.IsNullOrWhiteSpace(factor))
            && options.CredentialProviderKeys.Count > 0
            && options.CredentialProviderKeys.All(key => key.Type != default && !string.IsNullOrWhiteSpace(key.Name));
    }
}
