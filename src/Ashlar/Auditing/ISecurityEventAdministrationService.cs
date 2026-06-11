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
    /// <param name="request">The search request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result<SecurityEventSearchResult>> SearchSecurityEventsAsync(SearchSecurityEventsRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets a recorded security event by id.
    /// </summary>
    /// <param name="request">The detail request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result<SecurityEventSummary>> GetSecurityEventAsync(SecurityEventAdministrationDetailRequest request, CancellationToken cancellationToken = default);
}
