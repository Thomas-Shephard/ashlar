namespace Ashlar.Identity.Abstractions.Repositories;

/// <summary>
/// Indicates that a credential provider key is already linked to a different user.
/// </summary>
public sealed class CredentialProviderKeyConflictException : InvalidOperationException
{
    /// <summary>
    /// Creates an exception for a credential provider key already linked to another user.
    /// </summary>
    public CredentialProviderKeyConflictException()
        : base("Credential provider key is already linked to another user.")
    {
    }
}
