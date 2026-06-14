using Ashlar.Auditing;
using Ashlar.Identity.RateLimiting.Abstractions;

namespace Ashlar.Identity.Features.Administration;

/// <summary>
/// Implements safe administrator authentication rate-limit bucket search, detail, and reset operations.
/// </summary>
/// <param name="repository">Repository used for provider-backed bucket administration.</param>
/// <param name="dependencies">Optional dependencies used for time and audit emission.</param>
/// <remarks>
/// These operations are intended for administrative diagnostics and operations tooling and do not authorize the caller.
/// Host applications must protect usage of this service with appropriate admin authorization and step-up policy.
/// </remarks>
public sealed class AuthenticationRateLimitAdministrationService(
    IAuthenticationRateLimitAdministrationRepository repository,
    AuthenticationRateLimitAdministrationServiceDependencies? dependencies = null)
    : IAuthenticationRateLimitAdministrationService
{
    internal const int MaximumLimit = 100;

    private readonly IAuthenticationRateLimitAdministrationRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly TimeProvider _timeProvider = dependencies?.TimeProvider ?? TimeProvider.System;
    private readonly ISecurityEventSink? _securityEventSink = dependencies?.SecurityEventSink;

    /// <inheritdoc />
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

    /// <inheritdoc />
    public async Task<Result<AuthenticationRateLimitBucketDetail>> GetBucketAsync(AuthenticationRateLimitBucketDetailRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!TryValidateDetailRequest(request, out var validationFailure))
        {
            return validationFailure;
        }

        var bucket = await _repository.GetBucketAsync(request, _timeProvider.GetUtcNow(), cancellationToken);
        return bucket == null
            ? Result.Failure<AuthenticationRateLimitBucketDetail>(AshlarFailureCodes.RateLimitBucketNotFound, "Rate-limit bucket was not found.")
            : Result.Success(bucket);
    }

    /// <inheritdoc />
    public async Task<Result<AuthenticationRateLimitBucketResetResult>> ResetBucketAsync(ResetAuthenticationRateLimitBucketRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!TryValidateResetRequest(request, out var validationFailure))
        {
            return validationFailure;
        }

        try
        {
            var reset = await _repository.ResetBucketAsync(request, cancellationToken);
            var status = reset ? AuthenticationRateLimitBucketResetStatus.Reset : AuthenticationRateLimitBucketResetStatus.NotFound;
            var result = new AuthenticationRateLimitBucketResetResult(request.BucketId, request.Purpose, status);

            if (reset && _securityEventSink != null)
            {
                await SecurityEventAuditEmission.RecordCompletedOperationAsync(
                    _securityEventSink,
                    _timeProvider,
                    AshlarSecurityEventTypes.AuthenticationRateLimitBucketReset,
                    request.Audit,
                    new Dictionary<string, string>
                    {
                        ["purpose"] = request.Purpose,
                        ["bucket_id"] = request.BucketId
                    },
                    cancellationToken);
            }

            return Result.Success(result);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            return Result.Success(new AuthenticationRateLimitBucketResetResult(
                request.BucketId,
                request.Purpose,
                AuthenticationRateLimitBucketResetStatus.Failed));
        }
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

    private static bool TryValidateDetailRequest(AuthenticationRateLimitBucketDetailRequest request, out Result<AuthenticationRateLimitBucketDetail> failure)
    {
        try
        {
            AuthenticationRateLimitBucketDetailRequest.ThrowIfInvalid(request);
            failure = null!;
            return true;
        }
        catch (ArgumentException exception)
        {
            failure = Result.Failure<AuthenticationRateLimitBucketDetail>(AshlarFailureCodes.ValidationError, exception.Message);
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

/// <summary>
/// Optional dependencies for authentication rate-limit administration operations.
/// </summary>
/// <param name="TimeProvider">Clock used for status projection and audit timestamps.</param>
/// <param name="SecurityEventSink">Optional sink used to record successful reset events.</param>
public sealed record AuthenticationRateLimitAdministrationServiceDependencies(
    TimeProvider? TimeProvider = null,
    ISecurityEventSink? SecurityEventSink = null);
