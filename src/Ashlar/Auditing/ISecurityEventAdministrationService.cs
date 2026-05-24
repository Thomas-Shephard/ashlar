namespace Ashlar.Auditing;

/// <summary>
/// Provides read-only administrator security event browsing operations.
/// </summary>
public interface ISecurityEventAdministrationService
{
    /// <summary>
    /// Searches recorded security events.
    /// </summary>
    /// <param name="request">The search request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result<SecurityEventSearchResult>> SearchSecurityEventsAsync(SearchSecurityEventsRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets a recorded security event by id.
    /// </summary>
    /// <param name="eventId">The event id value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result<SecurityEventSummary>> GetSecurityEventAsync(Guid eventId, CancellationToken cancellationToken = default);
}
