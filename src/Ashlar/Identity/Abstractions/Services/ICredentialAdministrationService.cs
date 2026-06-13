namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Provides read-only administrator credential browsing operations.
/// </summary>
/// <remarks>
/// These operations are intended for administrative and operations tooling and do not authorize the caller.
/// Host applications must protect usage of this service with appropriate admin authorization and step-up policy.
/// </remarks>
public interface ICredentialAdministrationService
{
    /// <summary>
    /// Searches credentials using provider-neutral display fields.
    /// </summary>
    /// <param name="request">Tenant scope, filters, and paging options for the search.</param>
    /// <param name="cancellationToken">A token that can cancel the search.</param>
    /// <returns>Provider-neutral credential summaries. Credential secrets are never returned.</returns>
    Task<Result<CredentialSearchResult>> SearchCredentialsAsync(SearchCredentialsRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets safe credential detail by credential id.
    /// </summary>
    /// <param name="request">Tenant scope and credential identifier for the lookup.</param>
    /// <param name="cancellationToken">A token that can cancel the lookup.</param>
    /// <returns>Safe credential detail without credential secret values.</returns>
    Task<Result<CredentialAdministrationDetail>> GetCredentialAsync(CredentialAdministrationDetailRequest request, CancellationToken cancellationToken = default);
}
