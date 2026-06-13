namespace Ashlar.Auditing;

/// <summary>
/// Implements read-only administrator security event search and detail operations.
/// </summary>
/// <param name="repository">Repository used for safe administrator security event lookup.</param>
/// <remarks>
/// These operations are intended for administrative diagnostics and do not authorize the caller.
/// Host applications must protect usage of this service with appropriate admin authorization and step-up policy.
/// </remarks>
public sealed class SecurityEventAdministrationService(ISecurityEventAdministrationRepository repository) : ISecurityEventAdministrationService
{
    internal const int MaximumLimit = 100;

    private readonly ISecurityEventAdministrationRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));

    /// <inheritdoc />
    public async Task<Result<SecurityEventSearchResult>> SearchSecurityEventsAsync(SearchSecurityEventsRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!TryValidateSearchRequest(request, out var validationFailure))
        {
            return validationFailure;
        }

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
    public async Task<Result<SecurityEventSummary>> GetSecurityEventAsync(SecurityEventAdministrationDetailRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!TryValidateDetailRequest(request, out var validationFailure))
        {
            return validationFailure;
        }

        var securityEvent = await _repository.GetSecurityEventAsync(request, cancellationToken);
        return securityEvent == null || (!request.IncludeAllTenants && !AdministrationScopeValidation.IncludesTenant(request.Tenant!, securityEvent.TenantId))
            ? Result.Failure<SecurityEventSummary>(AshlarFailureCodes.SecurityEventNotFound, "Security event was not found.")
            : Result.Success(securityEvent);
    }

    private static bool TryValidateSearchRequest(SearchSecurityEventsRequest request, out Result<SecurityEventSearchResult> failure)
    {
        try
        {
            SearchSecurityEventsRequest.ThrowIfInvalid(request);
            failure = null!;
            return true;
        }
        catch (ArgumentException exception)
        {
            failure = Result.Failure<SecurityEventSearchResult>(AshlarFailureCodes.ValidationError, exception.Message);
            return false;
        }
    }

    private static bool TryValidateDetailRequest(SecurityEventAdministrationDetailRequest request, out Result<SecurityEventSummary> failure)
    {
        try
        {
            SecurityEventAdministrationDetailRequest.ThrowIfInvalid(request);
            failure = null!;
            return true;
        }
        catch (ArgumentException exception)
        {
            failure = Result.Failure<SecurityEventSummary>(AshlarFailureCodes.ValidationError, exception.Message);
            return false;
        }
    }
}
