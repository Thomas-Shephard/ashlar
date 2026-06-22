namespace Ashlar.Identity.Abstractions.Repositories;

/// <summary>
/// Provides read-only administrator credential lookup operations.
/// </summary>
/// <remarks>
/// Implementations must not expose credential values, provider keys, metadata, versions, hashes, tokens, secrets, or provider-specific raw identifiers.
/// </remarks>
public interface ICredentialAdministrationRepository
{
    /// <summary>
    /// Searches credentials using safe administrator-display fields.
    /// </summary>
    /// <param name="request">Search filters and tenant scope supplied by an authorized administrator flow.</param>
    /// <param name="now">The timestamp used for availability filtering and projection.</param>
    /// <param name="cancellationToken">A token that can cancel the search.</param>
    /// <returns>The matching credentials.</returns>
    Task<IReadOnlyList<CredentialAdministrationSummary>> SearchCredentialsAsync(SearchCredentialsRequest request, DateTimeOffset now, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets a safe credential projection by credential id.
    /// </summary>
    /// <param name="request">Credential identifier and tenant scope supplied by an authorized administrator flow.</param>
    /// <param name="now">The timestamp used for availability projection.</param>
    /// <param name="cancellationToken">A token that can cancel lookup.</param>
    /// <returns>The matching credential projection, or <see langword="null" /> when it does not exist.</returns>
    Task<CredentialAdministrationSummary?> GetCredentialAsync(CredentialAdministrationLookupRequest request, DateTimeOffset now, CancellationToken cancellationToken = default);
}
