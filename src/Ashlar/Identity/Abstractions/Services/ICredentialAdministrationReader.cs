namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Provides read-only administrator credential browsing operations.
/// </summary>
/// <remarks>
/// Every operation enforces actor, active-session proof, scope, host authorization, and durable audit requirements.
/// </remarks>
public interface ICredentialAdministrationReader
{
    /// <summary>
    /// Searches credentials using provider-neutral display fields.
    /// </summary>
    /// <param name="actor">Authenticated actor, active session, fresh proof, and audit metadata.</param>
    /// <param name="request">Tenant scope, filters, and paging options for the search.</param>
    /// <param name="cancellationToken">A token that can cancel the search.</param>
    /// <returns>Provider-neutral credential summaries. Credential secrets are never returned.</returns>
    Task<Result<CredentialSearchResult>> SearchCredentialsAsync(AccountSecurityActorContext actor, SearchCredentialsRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets a safe credential projection by credential id.
    /// </summary>
    /// <param name="actor">Authenticated actor, active session, fresh proof, and audit metadata.</param>
    /// <param name="request">Tenant scope and credential identifier for the lookup.</param>
    /// <param name="cancellationToken">A token that can cancel the lookup.</param>
    /// <returns>The same provider-neutral credential projection used by search when found, without credential secret values.</returns>
    Task<Result<CredentialAdministrationSummary>> GetCredentialAsync(AccountSecurityActorContext actor, CredentialAdministrationLookupRequest request, CancellationToken cancellationToken = default);
}
