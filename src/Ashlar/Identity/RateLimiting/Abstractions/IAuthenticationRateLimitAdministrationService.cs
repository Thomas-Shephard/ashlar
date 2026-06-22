namespace Ashlar.Identity.RateLimiting.Abstractions;

/// <summary>
/// Provides safe administrator operations for browsing and resetting authentication rate-limit buckets.
/// </summary>
/// <remarks>
/// Bucket identifiers returned by this service are opaque operational identifiers derived from stored hashed keys.
/// They are not raw rate-limit inputs and must not be treated as IP addresses, email addresses, user identifiers, tokens, or Redis key names.
/// Host applications must protect usage of this service with appropriate administrator authorization and step-up policy.
/// The service is registered by provider-backed rate limiter packages that support administration; the default in-memory limiter does not expose an administration implementation.
/// Searches are capped at 100 buckets per page. Redis-backed searches use a bounded key scan, so paging can be approximate while Redis keys change concurrently.
/// </remarks>
public interface IAuthenticationRateLimitAdministrationService
{
    /// <summary>
    /// Searches authentication rate-limit buckets using safe operational filters.
    /// </summary>
    /// <param name="request">Search filters and paging options.</param>
    /// <param name="cancellationToken">Token for aborting administration storage work.</param>
    /// <returns>A result containing a page of safe bucket summaries.</returns>
    Task<Result<AuthenticationRateLimitBucketSearchResult>> SearchBucketsAsync(SearchAuthenticationRateLimitBucketsRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Loads a single authentication rate-limit bucket by opaque bucket identifier and purpose.
    /// </summary>
    /// <param name="request">Lookup request containing the bucket identifier and purpose.</param>
    /// <param name="cancellationToken">Token for aborting administration storage work.</param>
    /// <returns>A result containing a safe bucket summary, or a not-found failure.</returns>
    Task<Result<AuthenticationRateLimitBucketSummary>> GetBucketAsync(AuthenticationRateLimitBucketLookupRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Resets a selected authentication rate-limit bucket.
    /// </summary>
    /// <param name="request">Reset request containing the bucket identifier, purpose, and audit context.</param>
    /// <param name="cancellationToken">Token for aborting administration storage work.</param>
    /// <returns>A result describing whether the selected bucket was reset.</returns>
    Task<Result<AuthenticationRateLimitBucketResetResult>> ResetBucketAsync(ResetAuthenticationRateLimitBucketRequest request, CancellationToken cancellationToken = default);
}
