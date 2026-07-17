using Ashlar.Identity.RateLimiting.Abstractions;

namespace Ashlar.Identity.Features.Administration;

internal sealed class AuthenticationRateLimitAdministrationReader(IAuthenticationRateLimitAdministrationReaderRepository repository, TimeProvider? timeProvider = null)
    : IAuthenticationRateLimitAdministrationReader
{
    private readonly IAuthenticationRateLimitAdministrationReaderRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    public async Task<Result<AuthenticationRateLimitBucketSearchResult>> SearchBucketsAsync(SearchAuthenticationRateLimitBucketsRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!AuthenticationRateLimitAdministrationService.TryValidateSearchRequest(request, out var failure)) return failure;
        if (request.Offset < 0) return Result.Failure<AuthenticationRateLimitBucketSearchResult>(AshlarFailureCodes.ValidationError, "Offset cannot be negative.");
        if (request.Limit < 1) return Result.Failure<AuthenticationRateLimitBucketSearchResult>(AshlarFailureCodes.ValidationError, "Limit must be greater than zero.");

        var limit = Math.Min(request.Limit, AuthenticationRateLimitAdministrationService.MaximumLimit);
        var buckets = await _repository.SearchBucketsAsync(request with { Limit = limit + 1 }, _timeProvider.GetUtcNow(), cancellationToken);
        return Result.Success(new AuthenticationRateLimitBucketSearchResult(buckets.Take(limit).ToList().AsReadOnly(), limit, request.Offset, buckets.Count > limit));
    }

    public async Task<Result<AuthenticationRateLimitBucketSummary>> GetBucketAsync(AuthenticationRateLimitBucketLookupRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!AuthenticationRateLimitAdministrationService.TryValidateLookupRequest(request, out var failure)) return failure;
        var bucket = await _repository.GetBucketAsync(request, _timeProvider.GetUtcNow(), cancellationToken);
        return bucket == null
            ? Result.Failure<AuthenticationRateLimitBucketSummary>(AshlarFailureCodes.RateLimitBucketNotFound, "Rate-limit bucket was not found.")
            : Result.Success(bucket);
    }
}
