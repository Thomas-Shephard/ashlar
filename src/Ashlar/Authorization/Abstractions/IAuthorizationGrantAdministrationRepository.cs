using Ashlar.Authorization.Models;

namespace Ashlar.Authorization.Abstractions;

/// <summary>
/// Provides read-only administrator authorization grant lookup operations.
/// </summary>
/// <remarks>
/// Infrastructure-only provider contract. It performs no actor authorization and must only be called by
/// <see cref="IAuthorizationGrantAdministrationService" />, which enforces actor proof, session, scope, audit, and host authorization.
/// Implementations must return display-safe grant projections and must not expose raw grant metadata.
/// </remarks>
public interface IAuthorizationGrantAdministrationRepository
{
    /// <summary>
    /// Searches authorization grants using safe administrator-display fields.
    /// </summary>
    /// <param name="request">Search filters and tenant scope supplied by an authorized administrator flow.</param>
    /// <param name="now">The timestamp used for status filtering and projection.</param>
    /// <param name="cancellationToken">A token that can cancel the search.</param>
    /// <returns>The matching authorization grants.</returns>
    Task<IReadOnlyList<AuthorizationGrantAdministrationSummary>> SearchAuthorizationGrantsAsync(SearchAuthorizationGrantsRequest request, DateTimeOffset now, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets an authorization grant by id.
    /// </summary>
    /// <param name="request">Grant identifier and tenant scope supplied by an authorized administrator flow.</param>
    /// <param name="now">The timestamp used for status projection.</param>
    /// <param name="cancellationToken">A token that can cancel lookup.</param>
    /// <returns>The authorization grant, or <see langword="null" /> when it does not exist.</returns>
    Task<AuthorizationGrantAdministrationSummary?> GetAuthorizationGrantAsync(AuthorizationGrantAdministrationLookupRequest request, DateTimeOffset now, CancellationToken cancellationToken = default);
}
