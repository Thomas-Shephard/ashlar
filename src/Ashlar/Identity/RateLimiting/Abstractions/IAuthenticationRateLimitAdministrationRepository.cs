namespace Ashlar.Identity.RateLimiting.Abstractions;

/// <summary>
/// Provider storage abstraction for safe authentication rate-limit administration operations.
/// </summary>
public interface IAuthenticationRateLimitAdministrationRepository
{
    /// <summary>
    /// Searches persisted authentication rate-limit buckets without exposing raw key material.
    /// </summary>
    /// <param name="request">Validated search request.</param>
    /// <param name="now">Current UTC time used for status projection.</param>
    /// <param name="cancellationToken">Token for aborting administration storage work.</param>
    /// <returns>A list of safe bucket summaries.</returns>
    Task<IReadOnlyList<AuthenticationRateLimitBucketSummary>> SearchBucketsAsync(SearchAuthenticationRateLimitBucketsRequest request, DateTimeOffset now, CancellationToken cancellationToken = default);

    /// <summary>
    /// Loads safe detail for a single persisted authentication rate-limit bucket.
    /// </summary>
    /// <param name="request">Validated detail request.</param>
    /// <param name="now">Current UTC time used for status projection.</param>
    /// <param name="cancellationToken">Token for aborting administration storage work.</param>
    /// <returns>The bucket detail when found; otherwise <see langword="null" />.</returns>
    Task<AuthenticationRateLimitBucketDetail?> GetBucketAsync(AuthenticationRateLimitBucketDetailRequest request, DateTimeOffset now, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a selected authentication rate-limit bucket.
    /// </summary>
    /// <param name="request">Validated reset request.</param>
    /// <param name="cancellationToken">Token for aborting administration storage work.</param>
    /// <returns><see langword="true" /> when a bucket was deleted; otherwise <see langword="false" />.</returns>
    Task<bool> ResetBucketAsync(ResetAuthenticationRateLimitBucketRequest request, CancellationToken cancellationToken = default);
}
