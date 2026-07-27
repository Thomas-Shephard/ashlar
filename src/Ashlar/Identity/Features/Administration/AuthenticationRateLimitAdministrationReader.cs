using Ashlar.Auditing;
using Ashlar.Identity.RateLimiting.Abstractions;

namespace Ashlar.Identity.Features.Administration;

internal sealed class AuthenticationRateLimitAdministrationReader(IAuthenticationRateLimitAdministrationReaderRepository repository,
    IAuthenticationSessionRepository sessions, IAccountSecurityOperationAuthorizer authorizer,
    IPersistentSecurityEventSink auditSink, TimeProvider? timeProvider = null)
    : IAuthenticationRateLimitAdministrationReader
{
    private readonly IAuthenticationRateLimitAdministrationReaderRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;
    private readonly AccountSecurityOperationBoundary _boundary = new(sessions, authorizer, auditSink, timeProvider ?? TimeProvider.System);

    public async Task<Result<AuthenticationRateLimitBucketSearchResult>> SearchBucketsAsync(AccountSecurityActorContext actor, AuthenticationRateLimitAdministrationScope scope, SearchAuthenticationRateLimitBucketsRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!AuthenticationRateLimitAdministrationService.TryValidateSearchRequest(request, out var failure)) return failure;
        if (request.Offset < 0) return Result.Failure<AuthenticationRateLimitBucketSearchResult>(AshlarFailureCodes.ValidationError, "Offset cannot be negative.");
        if (request.Limit < 1) return Result.Failure<AuthenticationRateLimitBucketSearchResult>(AshlarFailureCodes.ValidationError, "Limit must be greater than zero.");
        if (scope != AuthenticationRateLimitAdministrationScope.Global)
            return Result.Failure<AuthenticationRateLimitBucketSearchResult>(AshlarFailureCodes.ValidationError, "Rate-limit administration requires global operational scope.");
        if (!await _boundary.AuthorizeAsync(actor, null, true, Guid.Empty,
                AccountSecurityOperation.SearchAuthenticationRateLimitBuckets, cancellationToken)) return Result.Failure<AuthenticationRateLimitBucketSearchResult>(AshlarFailureCodes.ValidationError);

        var limit = Math.Min(request.Limit, AuthenticationRateLimitAdministrationService.MaximumLimit);
        var buckets = await _repository.SearchBucketsAsync(request with { Limit = limit + 1 }, _timeProvider.GetUtcNow(), cancellationToken);
        if (buckets.Any(bucket => request.Purpose != null && !string.Equals(bucket.Purpose, request.Purpose, StringComparison.Ordinal)))
        {
            await _boundary.RecordFailureAsync(actor, null, true, AccountSecurityOperation.SearchAuthenticationRateLimitBuckets);
            return Result.Failure<AuthenticationRateLimitBucketSearchResult>(AshlarFailureCodes.ValidationError);
        }
        await _boundary.RecordSuccessAsync(actor, null, true, AccountSecurityOperation.SearchAuthenticationRateLimitBuckets);
        return Result.Success(new AuthenticationRateLimitBucketSearchResult(buckets.Take(limit).ToList().AsReadOnly(), limit, request.Offset, buckets.Count > limit));
    }

    public async Task<Result<AuthenticationRateLimitBucketSummary>> GetBucketAsync(AccountSecurityActorContext actor, AuthenticationRateLimitAdministrationScope scope, AuthenticationRateLimitBucketLookupRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!AuthenticationRateLimitAdministrationService.TryValidateLookupRequest(request, out var failure)) return failure;
        if (scope != AuthenticationRateLimitAdministrationScope.Global)
            return Result.Failure<AuthenticationRateLimitBucketSummary>(AshlarFailureCodes.ValidationError, "Rate-limit administration requires global operational scope.");
        if (!await _boundary.AuthorizeAsync(actor, null, true, Guid.Empty,
                AccountSecurityOperation.ReadAuthenticationRateLimitBucket, cancellationToken)) return Result.Failure<AuthenticationRateLimitBucketSummary>(AshlarFailureCodes.ValidationError);
        var bucket = await _repository.GetBucketAsync(request, _timeProvider.GetUtcNow(), cancellationToken);
        if (bucket == null || !string.Equals(bucket.BucketId, request.BucketId, StringComparison.Ordinal)
            || !string.Equals(bucket.Purpose, request.Purpose, StringComparison.Ordinal))
        {
            await _boundary.RecordFailureAsync(actor, null, true, AccountSecurityOperation.ReadAuthenticationRateLimitBucket);
            return Result.Failure<AuthenticationRateLimitBucketSummary>(AshlarFailureCodes.RateLimitBucketNotFound, "Rate-limit bucket was not found.");
        }
        await _boundary.RecordSuccessAsync(actor, null, true, AccountSecurityOperation.ReadAuthenticationRateLimitBucket);
        return Result.Success(bucket);
    }
}
