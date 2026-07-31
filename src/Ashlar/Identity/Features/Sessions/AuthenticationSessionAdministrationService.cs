using Ashlar.Auditing;

namespace Ashlar.Identity.Features.Sessions;

/// <summary>
/// Implements read-only administrator authentication session search and single-item lookup operations.
/// </summary>
/// <param name="repository">Repository used for safe administrator session lookup.</param>
/// <param name="sessions">Authoritative session repository.</param>
/// <param name="authorizer">Required host authorization policy.</param>
/// <param name="auditSink">Required durable audit sink.</param>
/// <param name="timeProvider">Clock used for active-session projection.</param>
/// <remarks>
/// Every operation enforces actor-bound active-session proof, scope, host authorization, and durable audit requirements.
/// </remarks>
public sealed class AuthenticationSessionAdministrationService(
    IAuthenticationSessionAdministrationRepository repository,
    IAuthenticationSessionRepository sessions,
    IAccountSecurityOperationAuthorizer authorizer,
    IPersistentSecurityEventSink auditSink,
    TimeProvider? timeProvider = null)
    : IAuthenticationSessionAdministrationService
{
    internal const int MaximumLimit = 100;

    private readonly IAuthenticationSessionAdministrationRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;
    private readonly AccountSecurityOperationBoundary _boundary = new(sessions, authorizer, auditSink, timeProvider ?? TimeProvider.System);

    /// <inheritdoc />
    public async Task<Result<AuthenticationSessionSearchResult>> SearchAuthenticationSessionsAsync(SearchAuthenticationSessionsRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!TryValidateSearchRequest(request, out var validationFailure))
        {
            return validationFailure;
        }

        if (request.Offset < 0)
        {
            return Result.Failure<AuthenticationSessionSearchResult>(AshlarFailureCodes.ValidationError, "Offset cannot be negative.");
        }

        if (request.Limit < 1)
        {
            return Result.Failure<AuthenticationSessionSearchResult>(AshlarFailureCodes.ValidationError, "Limit must be greater than zero.");
        }

        if (await _boundary.AuthorizeAsync(request.Actor, request.Tenant, request.IncludeAllTenants,
                request.UserId ?? Guid.Empty, AccountSecurityOperation.SearchAuthenticationSessions, cancellationToken) is { } authorizationFailure)
            return Result.Failure<AuthenticationSessionSearchResult>(authorizationFailure);

        var limit = Math.Min(request.Limit, MaximumLimit);
        var repositoryRequest = request with { Actor = null, Limit = limit + 1 };
        var now = _timeProvider.GetUtcNow();
        List<AuthenticationSessionAdministrationSummary> results;
        try
        {
            results = (await _repository.SearchAuthenticationSessionsAsync(repositoryRequest, now, cancellationToken)).ToList();
        }
        catch
        {
            await _boundary.RecordFailureAsync(request.Actor!, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.SearchAuthenticationSessions);
            throw;
        }
        if (results.Any(session => !AdministrationScopeValidation.IncludesResult(request.Tenant, request.IncludeAllTenants,
                session.TenantId, request.UserId, session.UserId)))
        {
            await _boundary.RecordFailureAsync(request.Actor!, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.SearchAuthenticationSessions);
            throw new InvalidOperationException("The authentication-session administration provider returned a result outside the authorized scope.");
        }
        await _boundary.RecordSuccessAsync(request.Actor!, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.SearchAuthenticationSessions);
        var hasMore = results.Count > limit;
        var page = results.Take(limit).ToList().AsReadOnly();

        return Result.Success(new AuthenticationSessionSearchResult(page, limit, request.Offset, hasMore));
    }

    /// <inheritdoc />
    public async Task<Result<AuthenticationSessionAdministrationSummary>> GetAuthenticationSessionAsync(AuthenticationSessionAdministrationLookupRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!TryValidateLookupRequest(request, out var validationFailure))
        {
            return validationFailure;
        }

        if (await _boundary.AuthorizeAsync(request.Actor, request.Tenant, request.IncludeAllTenants,
                Guid.Empty, AccountSecurityOperation.ReadAuthenticationSession, cancellationToken) is { } authorizationFailure)
            return Result.Failure<AuthenticationSessionAdministrationSummary>(authorizationFailure);

        AuthenticationSessionAdministrationSummary? session;
        try
        {
            session = await _repository.GetAuthenticationSessionAsync(request with { Actor = null }, _timeProvider.GetUtcNow(), cancellationToken);
        }
        catch
        {
            await _boundary.RecordFailureAsync(request.Actor!, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.ReadAuthenticationSession);
            throw;
        }
        if (session is null || session.Id != request.SessionId
            || !AdministrationScopeValidation.IncludesResult(request.Tenant, request.IncludeAllTenants, session.TenantId))
        {
            await _boundary.RecordFailureAsync(request.Actor!, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.ReadAuthenticationSession);
            session = null;
        }
        else if (await _boundary.AuthorizeAsync(request.Actor, request.Tenant, request.IncludeAllTenants,
                session.UserId, AccountSecurityOperation.ReadAuthenticationSession, cancellationToken) is not null)
            session = null;
        else
            await _boundary.RecordSuccessAsync(request.Actor!, request.Tenant, request.IncludeAllTenants,
                AccountSecurityOperation.ReadAuthenticationSession);
        return session == null
            ? Result.Failure<AuthenticationSessionAdministrationSummary>(AshlarFailureCodes.SessionNotFound, "Session was not found.")
            : Result.Success(session);
    }

    private static bool TryValidateSearchRequest(SearchAuthenticationSessionsRequest request, out Result<AuthenticationSessionSearchResult> failure)
    {
        try
        {
            SearchAuthenticationSessionsRequest.ThrowIfInvalid(request);
            failure = null!;
            return true;
        }
        catch (ArgumentException exception)
        {
            failure = Result.Failure<AuthenticationSessionSearchResult>(AshlarFailureCodes.ValidationError, exception.Message);
            return false;
        }
    }

    private static bool TryValidateLookupRequest(AuthenticationSessionAdministrationLookupRequest request, out Result<AuthenticationSessionAdministrationSummary> failure)
    {
        try
        {
            AuthenticationSessionAdministrationLookupRequest.ThrowIfInvalid(request);
            failure = null!;
            return true;
        }
        catch (ArgumentException exception)
        {
            failure = Result.Failure<AuthenticationSessionAdministrationSummary>(AshlarFailureCodes.ValidationError, exception.Message);
            return false;
        }
    }
}
