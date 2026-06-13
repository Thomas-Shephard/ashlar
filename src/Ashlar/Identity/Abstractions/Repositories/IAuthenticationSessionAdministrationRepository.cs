namespace Ashlar.Identity.Abstractions.Repositories;

/// <summary>
/// Provides read-only administrator authentication session lookup operations.
/// </summary>
/// <remarks>
/// Implementations must not expose raw session tokens or token hashes.
/// </remarks>
public interface IAuthenticationSessionAdministrationRepository
{
    /// <summary>
    /// Searches authentication sessions using safe administrator-display fields.
    /// </summary>
    /// <param name="request">Search filters and tenant scope supplied by an authorized administrator flow.</param>
    /// <param name="now">The timestamp used for active-state filtering and projection.</param>
    /// <param name="cancellationToken">A token that can cancel the search.</param>
    /// <returns>The matching authentication sessions.</returns>
    Task<IReadOnlyList<AuthenticationSessionAdministrationSummary>> SearchAuthenticationSessionsAsync(SearchAuthenticationSessionsRequest request, DateTimeOffset now, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets an authentication session by id.
    /// </summary>
    /// <param name="request">Session identifier and tenant scope supplied by an authorized administrator flow.</param>
    /// <param name="now">The timestamp used for active-state projection.</param>
    /// <param name="cancellationToken">A token that can cancel lookup.</param>
    /// <returns>The authentication session, or <see langword="null" /> when it does not exist.</returns>
    Task<AuthenticationSessionAdministrationDetail?> GetAuthenticationSessionAsync(AuthenticationSessionAdministrationDetailRequest request, DateTimeOffset now, CancellationToken cancellationToken = default);
}
