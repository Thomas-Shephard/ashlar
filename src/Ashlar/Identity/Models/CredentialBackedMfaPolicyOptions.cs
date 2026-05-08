namespace Ashlar.Identity.Models;

/// <summary>
/// Configures an MFA policy that requires factors when qualifying user credentials exist.
/// </summary>
public sealed class CredentialBackedMfaPolicyOptions
{
    public IList<AuthenticationProviderKey> CredentialProviderKeys { get; } = [];

    public IList<string> RequiredFactors { get; } = [];

    public static bool Validate(CredentialBackedMfaPolicyOptions? options)
    {
        return options is not null
            && options.RequiredFactors.Count > 0
            && options.RequiredFactors.All(factor => !string.IsNullOrWhiteSpace(factor))
            && options.CredentialProviderKeys.Count > 0
            && options.CredentialProviderKeys.All(key => key.Type != default && !string.IsNullOrWhiteSpace(key.Name));
    }
}
