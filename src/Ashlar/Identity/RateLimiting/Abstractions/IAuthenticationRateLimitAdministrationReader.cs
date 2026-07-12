namespace Ashlar.Identity.RateLimiting.Abstractions;

/// <summary>Reads safe rate-limit bucket administration data without enabling resets.</summary>
public interface IAuthenticationRateLimitAdministrationReader
{
    /// <summary>Searches authentication rate-limit buckets using safe operational filters.</summary>
    /// <param name="request">Search filters and paging options.</param>
    /// <param name="cancellationToken">Token for aborting storage work.</param>
    /// <returns>A page of safe bucket summaries.</returns>
    Task<Result<AuthenticationRateLimitBucketSearchResult>> SearchBucketsAsync(SearchAuthenticationRateLimitBucketsRequest request, CancellationToken cancellationToken = default);

    /// <summary>Loads a single rate-limit bucket by opaque identifier and purpose.</summary>
    /// <param name="request">Lookup request containing the bucket identifier and purpose.</param>
    /// <param name="cancellationToken">Token for aborting storage work.</param>
    /// <returns>A safe bucket summary, or a not-found failure.</returns>
    Task<Result<AuthenticationRateLimitBucketSummary>> GetBucketAsync(AuthenticationRateLimitBucketLookupRequest request, CancellationToken cancellationToken = default);
}
