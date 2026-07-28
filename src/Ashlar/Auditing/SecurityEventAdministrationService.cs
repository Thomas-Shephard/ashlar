namespace Ashlar.Auditing;

/// <summary>
/// Implements read-only administrator security event search and detail operations.
/// </summary>
/// <param name="repository">Repository used for safe administrator security event lookup.</param>
/// <param name="sessions">Authoritative session repository.</param>
/// <param name="authorizer">Required host authorization policy.</param>
/// <param name="auditSink">Required durable audit sink.</param>
/// <param name="timeProvider">Clock used for proof validation and auditing.</param>
/// <remarks>
/// Every operation enforces actor-bound active-session proof, scope, host authorization, and durable audit requirements.
/// </remarks>
public sealed class SecurityEventAdministrationService(ISecurityEventAdministrationRepository repository,
    IAuthenticationSessionRepository sessions, IAccountSecurityOperationAuthorizer authorizer,
    IPersistentSecurityEventSink auditSink, TimeProvider? timeProvider = null) : ISecurityEventAdministrationService
{
    internal const int MaximumLimit = 100;

    private readonly ISecurityEventAdministrationRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly AccountSecurityOperationBoundary _boundary = new(sessions, authorizer, auditSink, timeProvider ?? TimeProvider.System);

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

        if (!await _boundary.AuthorizeAsync(request.Actor, request.Tenant, request.IncludeAllTenants,
                request.UserId ?? Guid.Empty, AccountSecurityOperation.SearchSecurityEvents, cancellationToken))
            return Result.Failure<SecurityEventSearchResult>(AshlarFailureCodes.ValidationError);

        var limit = Math.Min(request.Limit, MaximumLimit);
        var repositoryRequest = request with { Actor = null, Limit = limit + 1 };
        List<SecurityEventSummary> events;
        try
        {
            events = (await _repository.SearchSecurityEventsAsync(repositoryRequest, cancellationToken)).ToList();
        }
        catch
        {
            await _boundary.RecordFailureAsync(request.Actor!, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.SearchSecurityEvents);
            throw;
        }
        if (events.Any(securityEvent => !AdministrationScopeValidation.IncludesResult(request.Tenant, request.IncludeAllTenants,
                securityEvent.TenantId, request.UserId, securityEvent.UserId)))
        {
            await _boundary.RecordFailureAsync(request.Actor!, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.SearchSecurityEvents);
            throw new InvalidOperationException("The security-event administration provider returned a result outside the authorized scope.");
        }
        await _boundary.RecordSuccessAsync(request.Actor!, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.SearchSecurityEvents);
        var hasMore = events.Count > limit;
        var page = events.Take(limit).ToList().AsReadOnly();

        return Result.Success(new SecurityEventSearchResult(page, limit, request.Offset, hasMore));
    }

    /// <inheritdoc />
    public async Task<Result<SecurityEventSummary>> GetSecurityEventAsync(SecurityEventAdministrationDetailRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!TryValidateLookupRequest(request, out var validationFailure))
        {
            return validationFailure;
        }

        if (!await _boundary.AuthorizeAsync(request.Actor, request.Tenant, request.IncludeAllTenants,
                Guid.Empty, AccountSecurityOperation.ReadSecurityEvent, cancellationToken))
            return Result.Failure<SecurityEventSummary>(AshlarFailureCodes.ValidationError);

        SecurityEventSummary? securityEvent;
        try
        {
            securityEvent = await _repository.GetSecurityEventAsync(request with { Actor = null }, cancellationToken);
        }
        catch
        {
            await _boundary.RecordFailureAsync(request.Actor!, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.ReadSecurityEvent);
            throw;
        }
        if (securityEvent is null || securityEvent.EventId != request.EventId
            || !AdministrationScopeValidation.IncludesResult(request.Tenant, request.IncludeAllTenants, securityEvent.TenantId))
        {
            await _boundary.RecordFailureAsync(request.Actor!, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.ReadSecurityEvent);
            securityEvent = null;
        }
        else if (!await _boundary.AuthorizeAsync(request.Actor, request.Tenant, request.IncludeAllTenants,
                securityEvent.UserId ?? Guid.Empty, AccountSecurityOperation.ReadSecurityEvent, cancellationToken))
            securityEvent = null;
        if (securityEvent is not null)
            await _boundary.RecordSuccessAsync(request.Actor!, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.ReadSecurityEvent);
        return securityEvent == null
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

    private static bool TryValidateLookupRequest(SecurityEventAdministrationDetailRequest request, out Result<SecurityEventSummary> failure)
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
