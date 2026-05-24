namespace Ashlar.Auditing;

/// <summary>
/// Implements read-only administrator security event search and detail operations.
/// </summary>
/// <param name="repository">The repository value.</param>
/// <remarks>
/// These operations are intended for administrative diagnostics and do not authorize the caller.
/// Host applications must protect usage of this service with appropriate admin authorization.
/// </remarks>
public sealed class SecurityEventAdministrationService(ISecurityEventAdministrationRepository repository) : ISecurityEventAdministrationService
{
    internal const int MaximumLimit = 100;

    private readonly ISecurityEventAdministrationRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));

    /// <inheritdoc />
    public async Task<Result<SecurityEventSearchResult>> SearchSecurityEventsAsync(SearchSecurityEventsRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (request.Offset < 0)
        {
            return Result.Failure<SecurityEventSearchResult>(AshlarFailureCodes.ValidationError, "Offset cannot be negative.");
        }

        if (request.Limit < 1)
        {
            return Result.Failure<SecurityEventSearchResult>(AshlarFailureCodes.ValidationError, "Limit must be greater than zero.");
        }

        var limit = Math.Min(request.Limit, MaximumLimit);
        var repositoryRequest = request with { Limit = limit + 1 };
        var events = await _repository.SearchSecurityEventsAsync(repositoryRequest, cancellationToken);
        var hasMore = events.Count > limit;
        var page = events.Take(limit).ToList().AsReadOnly();

        return Result.Success(new SecurityEventSearchResult(page, limit, request.Offset, hasMore));
    }

    /// <inheritdoc />
    public async Task<Result<SecurityEventSummary>> GetSecurityEventAsync(Guid eventId, CancellationToken cancellationToken = default)
    {
        if (eventId == Guid.Empty)
        {
            return Result.Failure<SecurityEventSummary>(AshlarFailureCodes.ValidationError, "Event ID cannot be empty.");
        }

        var securityEvent = await _repository.GetSecurityEventAsync(eventId, cancellationToken);
        return securityEvent == null
            ? Result.Failure<SecurityEventSummary>(AshlarFailureCodes.SecurityEventNotFound, "Security event was not found.")
            : Result.Success(securityEvent);
    }
}
