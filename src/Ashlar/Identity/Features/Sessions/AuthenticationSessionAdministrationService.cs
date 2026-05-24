namespace Ashlar.Identity.Features.Sessions;

/// <summary>
/// Implements read-only administrator authentication session search and detail operations.
/// </summary>
/// <param name="repository">The repository value.</param>
/// <param name="timeProvider">The time provider value.</param>
/// <remarks>
/// These operations are intended for administrative diagnostics and operations tooling and do not authorize the caller.
/// Host applications must protect usage of this service with appropriate admin authorization and step-up policy.
/// </remarks>
public sealed class AuthenticationSessionAdministrationService(
    IAuthenticationSessionAdministrationRepository repository,
    TimeProvider? timeProvider = null)
    : IAuthenticationSessionAdministrationService
{
    internal const int MaximumLimit = 100;

    private readonly IAuthenticationSessionAdministrationRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    /// <inheritdoc />
    public async Task<Result<AuthenticationSessionSearchResult>> SearchAuthenticationSessionsAsync(SearchAuthenticationSessionsRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (request.Offset < 0)
        {
            return Result.Failure<AuthenticationSessionSearchResult>(AshlarFailureCodes.ValidationError, "Offset cannot be negative.");
        }

        if (request.Limit < 1)
        {
            return Result.Failure<AuthenticationSessionSearchResult>(AshlarFailureCodes.ValidationError, "Limit must be greater than zero.");
        }

        var limit = Math.Min(request.Limit, MaximumLimit);
        var repositoryRequest = request with { Limit = limit + 1 };
        var now = _timeProvider.GetUtcNow();
        var sessions = await _repository.SearchAuthenticationSessionsAsync(repositoryRequest, now, cancellationToken);
        var hasMore = sessions.Count > limit;
        var page = sessions.Take(limit).ToList().AsReadOnly();

        return Result.Success(new AuthenticationSessionSearchResult(page, limit, request.Offset, hasMore));
    }

    /// <inheritdoc />
    public async Task<Result<AuthenticationSessionAdministrationDetail>> GetAuthenticationSessionAsync(Guid sessionId, CancellationToken cancellationToken = default)
    {
        if (sessionId == Guid.Empty)
        {
            return Result.Failure<AuthenticationSessionAdministrationDetail>(AshlarFailureCodes.ValidationError, "Session ID cannot be empty.");
        }

        var session = await _repository.GetAuthenticationSessionAsync(sessionId, _timeProvider.GetUtcNow(), cancellationToken);
        return session == null
            ? Result.Failure<AuthenticationSessionAdministrationDetail>(AshlarFailureCodes.SessionNotFound, "Session was not found.")
            : Result.Success(session);
    }
}
