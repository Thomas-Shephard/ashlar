namespace Ashlar.Identity.Models;

/// <summary>
/// Configures an MFA policy that requires factors when qualifying user credentials exist.
/// </summary>
public sealed class CredentialBackedMfaPolicyOptions
{
    /// <summary>
    /// Gets or sets the credential provider keys value.
    /// </summary>
    public IList<AuthenticationProviderKey> CredentialProviderKeys { get; } = [];

    /// <summary>
    /// Gets or sets the required factors value.
    /// </summary>
    public IList<string> RequiredFactors { get; } = [];

    /// <summary>
    /// Performs the validate operation and returns the result.
    /// </summary>
    /// <param name="options">The options value.</param>
    /// <returns>The operation result.</returns>
    public static bool Validate(CredentialBackedMfaPolicyOptions? options)
    {
        return options is not null
            && options.RequiredFactors.Count > 0
            && options.RequiredFactors.All(factor => !string.IsNullOrWhiteSpace(factor))
            && options.CredentialProviderKeys.Count > 0
            && options.CredentialProviderKeys.All(key => key.Type != default && !string.IsNullOrWhiteSpace(key.Name));
    }
}
