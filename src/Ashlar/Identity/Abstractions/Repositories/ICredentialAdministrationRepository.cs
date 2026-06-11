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
    /// <param name="request">The search request value.</param>
    /// <param name="now">The timestamp used for availability filtering and projection.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The matching credentials.</returns>
    Task<IReadOnlyList<CredentialAdministrationSummary>> SearchCredentialsAsync(SearchCredentialsRequest request, DateTimeOffset now, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets safe credential detail by credential id.
    /// </summary>
    /// <param name="request">The detail request value.</param>
    /// <param name="now">The timestamp used for availability projection.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The credential, or <see langword="null" /> when it does not exist.</returns>
    Task<CredentialAdministrationDetail?> GetCredentialAsync(CredentialAdministrationDetailRequest request, DateTimeOffset now, CancellationToken cancellationToken = default);
}
