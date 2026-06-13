namespace Ashlar.Auditing;

/// <summary>
/// Provides read-only administrator security event browsing operations.
/// </summary>
/// <remarks>
/// These operations are intended for administrative and operations tooling and do not authorize the caller.
/// Host applications must protect usage of this service with appropriate admin authorization and step-up policy.
/// </remarks>
public interface ISecurityEventAdministrationService
{
    /// <summary>
    /// Searches recorded security events.
    /// </summary>
    /// <param name="request">Search filters and tenant scope supplied by an authorized administrator flow.</param>
    /// <param name="cancellationToken">A token that can cancel the search.</param>
    /// <returns>A result containing safe security event summaries, or a failure status.</returns>
    Task<Result<SecurityEventSearchResult>> SearchSecurityEventsAsync(SearchSecurityEventsRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets a recorded security event by id.
    /// </summary>
    /// <param name="request">Security event identifier and tenant scope supplied by an authorized administrator flow.</param>
    /// <param name="cancellationToken">A token that can cancel lookup.</param>
    /// <returns>A result containing the safe event summary, or a failure status.</returns>
    Task<Result<SecurityEventSummary>> GetSecurityEventAsync(SecurityEventAdministrationDetailRequest request, CancellationToken cancellationToken = default);
}
