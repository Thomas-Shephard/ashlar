namespace Ashlar.Identity.Abstractions.Repositories;

/// <summary>
/// Indicates that a credential provider key is already linked to a different user.
/// </summary>
public sealed class CredentialProviderKeyConflictException : InvalidOperationException
{
    /// <summary>
    /// Initializes a new instance of the credential provider key conflict exception.
    /// </summary>
    public CredentialProviderKeyConflictException()
        : base("Credential provider key is already linked to another user.")
    {
    }
}
