namespace Ashlar.Auditing;

/// <summary>
/// Provides read-only administrator security event lookup operations.
/// </summary>
public interface ISecurityEventAdministrationRepository
{
    /// <summary>
    /// Searches recorded security events using safe administrator-display fields.
    /// </summary>
    /// <param name="request">Search filters and tenant scope supplied by an authorized administrator flow.</param>
    /// <param name="cancellationToken">A token that can cancel the search.</param>
    /// <returns>The matching security events.</returns>
    Task<IReadOnlyList<SecurityEventSummary>> SearchSecurityEventsAsync(SearchSecurityEventsRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets a recorded security event by id.
    /// </summary>
    /// <param name="request">Security event identifier and tenant scope supplied by an authorized administrator flow.</param>
    /// <param name="cancellationToken">A token that can cancel lookup.</param>
    /// <returns>The security event, or <see langword="null" /> when it does not exist.</returns>
    Task<SecurityEventSummary?> GetSecurityEventAsync(SecurityEventAdministrationDetailRequest request, CancellationToken cancellationToken = default);
}
