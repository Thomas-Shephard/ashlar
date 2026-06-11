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

        var limit = Math.Min(request.Limit, MaximumLimit);
        var repositoryRequest = request with { Limit = limit + 1 };
        var now = _timeProvider.GetUtcNow();
        var sessions = await _repository.SearchAuthenticationSessionsAsync(repositoryRequest, now, cancellationToken);
        var hasMore = sessions.Count > limit;
        var page = sessions.Take(limit).ToList().AsReadOnly();

        return Result.Success(new AuthenticationSessionSearchResult(page, limit, request.Offset, hasMore));
    }

    /// <inheritdoc />
    public async Task<Result<AuthenticationSessionAdministrationDetail>> GetAuthenticationSessionAsync(AuthenticationSessionAdministrationDetailRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!TryValidateDetailRequest(request, out var validationFailure))
        {
            return validationFailure;
        }

        var session = await _repository.GetAuthenticationSessionAsync(request, _timeProvider.GetUtcNow(), cancellationToken);
        return session == null || (!request.IncludeAllTenants && !AdministrationScopeValidation.IncludesTenant(request.Tenant!, session.TenantId))
            ? Result.Failure<AuthenticationSessionAdministrationDetail>(AshlarFailureCodes.SessionNotFound, "Session was not found.")
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

    private static bool TryValidateDetailRequest(AuthenticationSessionAdministrationDetailRequest request, out Result<AuthenticationSessionAdministrationDetail> failure)
    {
        try
        {
            AuthenticationSessionAdministrationDetailRequest.ThrowIfInvalid(request);
            failure = null!;
            return true;
        }
        catch (ArgumentException exception)
        {
            failure = Result.Failure<AuthenticationSessionAdministrationDetail>(AshlarFailureCodes.ValidationError, exception.Message);
            return false;
        }
    }
}
