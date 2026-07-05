using Ashlar.Auditing;
using Ashlar.Identity.RateLimiting.Abstractions;

namespace Ashlar.Identity.Features.Administration;

internal sealed class AuthenticationRateLimitAdministrationService(
    IAuthenticationRateLimitAdministrationRepository repository,
    AuthenticationRateLimitAdministrationServiceDependencies? dependencies = null)
    : IAuthenticationRateLimitAdministrationService
{
    internal const int MaximumLimit = 100;

    private readonly IAuthenticationRateLimitAdministrationRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly TimeProvider _timeProvider = dependencies?.TimeProvider ?? TimeProvider.System;
    private readonly SecurityEventEmitter _securityEvents = new(dependencies?.SecurityEventSink, dependencies?.TimeProvider);

    public async Task<Result<AuthenticationRateLimitBucketSearchResult>> SearchBucketsAsync(SearchAuthenticationRateLimitBucketsRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!TryValidateSearchRequest(request, out var validationFailure))
        {
            return validationFailure;
        }

        if (request.Offset < 0)
        {
            return Result.Failure<AuthenticationRateLimitBucketSearchResult>(AshlarFailureCodes.ValidationError, "Offset cannot be negative.");
        }

        if (request.Limit < 1)
        {
            return Result.Failure<AuthenticationRateLimitBucketSearchResult>(AshlarFailureCodes.ValidationError, "Limit must be greater than zero.");
        }

        var limit = Math.Min(request.Limit, MaximumLimit);
        var repositoryRequest = request with { Limit = limit + 1 };
        var buckets = await _repository.SearchBucketsAsync(repositoryRequest, _timeProvider.GetUtcNow(), cancellationToken);
        var hasMore = buckets.Count > limit;
        var page = buckets.Take(limit).ToList().AsReadOnly();

        return Result.Success(new AuthenticationRateLimitBucketSearchResult(page, limit, request.Offset, hasMore));
    }

    public async Task<Result<AuthenticationRateLimitBucketSummary>> GetBucketAsync(AuthenticationRateLimitBucketLookupRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!TryValidateLookupRequest(request, out var validationFailure))
        {
            return validationFailure;
        }

        var bucket = await _repository.GetBucketAsync(request, _timeProvider.GetUtcNow(), cancellationToken);
        return bucket == null
            ? Result.Failure<AuthenticationRateLimitBucketSummary>(AshlarFailureCodes.RateLimitBucketNotFound, "Rate-limit bucket was not found.")
            : Result.Success(bucket);
    }

    public async Task<Result<AuthenticationRateLimitBucketResetResult>> ResetBucketAsync(ResetAuthenticationRateLimitBucketRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!TryValidateResetRequest(request, out var validationFailure))
        {
            return validationFailure;
        }

        AuthenticationRateLimitBucketResetResult result;
        try
        {
            var reset = await _repository.ResetBucketAsync(request, cancellationToken);
            var status = reset ? AuthenticationRateLimitBucketResetStatus.Reset : AuthenticationRateLimitBucketResetStatus.NotFound;
            result = new AuthenticationRateLimitBucketResetResult(request.BucketId, request.Purpose, status);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            result = new AuthenticationRateLimitBucketResetResult(
                request.BucketId,
                request.Purpose,
                AuthenticationRateLimitBucketResetStatus.Failed);
        }

        await RecordResetAttemptAsync(request, result.Status, cancellationToken);

        return Result.Success(result);
    }

    private Task RecordResetAttemptAsync(
        ResetAuthenticationRateLimitBucketRequest request,
        AuthenticationRateLimitBucketResetStatus status,
        CancellationToken cancellationToken)
    {
        var outcome = status == AuthenticationRateLimitBucketResetStatus.Reset
            ? SecurityEventOutcomes.Success
            : SecurityEventOutcomes.Failure;

        return _securityEvents.RecordAsync(
            new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.AuthenticationRateLimitBucketReset,
                Audit = request.Audit,
                Outcome = outcome,
                Properties = CreateResetAttemptProperties(request, status)
            },
            cancellationToken);
    }

    private static Dictionary<string, string> CreateResetAttemptProperties(
        ResetAuthenticationRateLimitBucketRequest request,
        AuthenticationRateLimitBucketResetStatus status)
    {
        return new Dictionary<string, string>
        {
            ["purpose"] = request.Purpose,
            ["bucket_id"] = request.BucketId,
            ["reset_status"] = status.ToString()
        };
    }

    private static bool TryValidateSearchRequest(SearchAuthenticationRateLimitBucketsRequest request, out Result<AuthenticationRateLimitBucketSearchResult> failure)
    {
        try
        {
            SearchAuthenticationRateLimitBucketsRequest.ThrowIfInvalid(request);
            failure = null!;
            return true;
        }
        catch (ArgumentException exception)
        {
            failure = Result.Failure<AuthenticationRateLimitBucketSearchResult>(AshlarFailureCodes.ValidationError, exception.Message);
            return false;
        }
    }

    private static bool TryValidateLookupRequest(AuthenticationRateLimitBucketLookupRequest request, out Result<AuthenticationRateLimitBucketSummary> failure)
    {
        try
        {
            AuthenticationRateLimitBucketLookupRequest.ThrowIfInvalid(request);
            failure = null!;
            return true;
        }
        catch (ArgumentException exception)
        {
            failure = Result.Failure<AuthenticationRateLimitBucketSummary>(AshlarFailureCodes.ValidationError, exception.Message);
            return false;
        }
    }

    private static bool TryValidateResetRequest(ResetAuthenticationRateLimitBucketRequest request, out Result<AuthenticationRateLimitBucketResetResult> failure)
    {
        try
        {
            ResetAuthenticationRateLimitBucketRequest.ThrowIfInvalid(request);
            failure = null!;
            return true;
        }
        catch (ArgumentException exception)
        {
            failure = Result.Failure<AuthenticationRateLimitBucketResetResult>(AshlarFailureCodes.ValidationError, exception.Message);
            return false;
        }
    }
}

internal sealed record AuthenticationRateLimitAdministrationServiceDependencies(
    TimeProvider? TimeProvider = null,
    ISecurityEventSink? SecurityEventSink = null);
