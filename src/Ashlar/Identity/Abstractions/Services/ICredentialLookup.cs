namespace Ashlar.Identity.Abstractions.Services;

/// <summary>Read-only credential lookup capability supplied to authentication providers.</summary>
public interface ICredentialLookup
{
    /// <summary>Retrieves a credential owned by a user for one provider identity.</summary>
    /// <param name="userId">User that must own the credential.</param>
    /// <param name="type">Provider category.</param>
    /// <param name="providerName">Provider name within its category.</param>
    /// <param name="providerKey">Optional provider credential key.</param>
    /// <param name="cancellationToken">Token that can cancel the lookup.</param>
    /// <returns>The matching credential, or <see langword="null" />.</returns>
    Task<UserCredential?> GetCredentialForUserAsync(Guid userId, ProviderType type, string providerName,
        string? providerKey = null, CancellationToken cancellationToken = default);
}
