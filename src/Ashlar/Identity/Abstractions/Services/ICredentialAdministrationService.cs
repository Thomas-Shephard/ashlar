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
    /// <param name="request">The search request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result<CredentialSearchResult>> SearchCredentialsAsync(SearchCredentialsRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets safe credential detail by credential id.
    /// </summary>
    /// <param name="credentialId">The credential id value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result<CredentialAdministrationDetail>> GetCredentialAsync(Guid credentialId, CancellationToken cancellationToken = default);
}
