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
    private readonly AdminReadBoundary _boundary = new(sessions, authorizer, auditSink, timeProvider ?? TimeProvider.System);

    public async Task<Result<AuthenticationRateLimitBucketSearchResult>> SearchBucketsAsync(AccountSecurityActorContext actor, TenantContext? tenant, bool includeAllTenants, SearchAuthenticationRateLimitBucketsRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!AuthenticationRateLimitAdministrationService.TryValidateSearchRequest(request, out var failure)) return failure;
        if (request.Offset < 0) return Result.Failure<AuthenticationRateLimitBucketSearchResult>(AshlarFailureCodes.ValidationError, "Offset cannot be negative.");
        if (request.Limit < 1) return Result.Failure<AuthenticationRateLimitBucketSearchResult>(AshlarFailureCodes.ValidationError, "Limit must be greater than zero.");
        try { AdministrationScopeValidation.ThrowIfInvalidScope(tenant, includeAllTenants); }
        catch (ArgumentException exception) { return Result.Failure<AuthenticationRateLimitBucketSearchResult>(AshlarFailureCodes.ValidationError, exception.Message); }
        if (!await _boundary.AuthorizeAsync(actor, tenant, includeAllTenants, Guid.Empty,
                AccountSecurityOperation.SearchAuthenticationRateLimitBuckets, cancellationToken)) return Result.Failure<AuthenticationRateLimitBucketSearchResult>(AshlarFailureCodes.ValidationError);

        var limit = Math.Min(request.Limit, AuthenticationRateLimitAdministrationService.MaximumLimit);
        var buckets = await _repository.SearchBucketsAsync(request with { Limit = limit + 1 }, _timeProvider.GetUtcNow(), cancellationToken);
        if (buckets.Any(bucket => request.Purpose != null && !string.Equals(bucket.Purpose, request.Purpose, StringComparison.Ordinal)))
        {
            await _boundary.RecordFailureAsync(actor, tenant, includeAllTenants, AccountSecurityOperation.SearchAuthenticationRateLimitBuckets);
            return Result.Failure<AuthenticationRateLimitBucketSearchResult>(AshlarFailureCodes.ValidationError);
        }
        await _boundary.RecordSuccessAsync(actor, tenant, includeAllTenants, AccountSecurityOperation.SearchAuthenticationRateLimitBuckets);
        return Result.Success(new AuthenticationRateLimitBucketSearchResult(buckets.Take(limit).ToList().AsReadOnly(), limit, request.Offset, buckets.Count > limit));
    }

    public async Task<Result<AuthenticationRateLimitBucketSummary>> GetBucketAsync(AccountSecurityActorContext actor, TenantContext? tenant, bool includeAllTenants, AuthenticationRateLimitBucketLookupRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!AuthenticationRateLimitAdministrationService.TryValidateLookupRequest(request, out var failure)) return failure;
        try { AdministrationScopeValidation.ThrowIfInvalidScope(tenant, includeAllTenants); }
        catch (ArgumentException exception) { return Result.Failure<AuthenticationRateLimitBucketSummary>(AshlarFailureCodes.ValidationError, exception.Message); }
        if (!await _boundary.AuthorizeAsync(actor, tenant, includeAllTenants, Guid.Empty,
                AccountSecurityOperation.ReadAuthenticationRateLimitBucket, cancellationToken)) return Result.Failure<AuthenticationRateLimitBucketSummary>(AshlarFailureCodes.ValidationError);
        var bucket = await _repository.GetBucketAsync(request, _timeProvider.GetUtcNow(), cancellationToken);
        if (bucket == null || !string.Equals(bucket.BucketId, request.BucketId, StringComparison.Ordinal)
            || !string.Equals(bucket.Purpose, request.Purpose, StringComparison.Ordinal))
        {
            await _boundary.RecordFailureAsync(actor, tenant, includeAllTenants, AccountSecurityOperation.ReadAuthenticationRateLimitBucket);
            return Result.Failure<AuthenticationRateLimitBucketSummary>(AshlarFailureCodes.RateLimitBucketNotFound, "Rate-limit bucket was not found.");
        }
        await _boundary.RecordSuccessAsync(actor, tenant, includeAllTenants, AccountSecurityOperation.ReadAuthenticationRateLimitBucket);
        return Result.Success(bucket);
    }
}
