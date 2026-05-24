namespace Ashlar.Auditing;

/// <summary>
/// Provides read-only administrator security event lookup operations.
/// </summary>
public interface ISecurityEventAdministrationRepository
{
    /// <summary>
    /// Searches recorded security events using safe administrator-display fields.
    /// </summary>
    /// <param name="request">The search request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The matching security events.</returns>
    Task<IReadOnlyList<SecurityEventSummary>> SearchSecurityEventsAsync(SearchSecurityEventsRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets a recorded security event by id.
    /// </summary>
    /// <param name="eventId">The event id value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The security event, or <see langword="null" /> when it does not exist.</returns>
    Task<SecurityEventSummary?> GetSecurityEventAsync(Guid eventId, CancellationToken cancellationToken = default);
}
