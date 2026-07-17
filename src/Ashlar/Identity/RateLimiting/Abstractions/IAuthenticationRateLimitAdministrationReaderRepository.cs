namespace Ashlar.Identity.RateLimiting.Abstractions;

/// <summary>
/// Provider storage abstraction for read-only authentication rate-limit administration.
/// </summary>
public interface IAuthenticationRateLimitAdministrationReaderRepository
{
    /// <summary>Searches persisted authentication rate-limit buckets without exposing raw key material.</summary>
    /// <param name="request">Validated search request.</param>
    /// <param name="now">Current UTC time used for status projection.</param>
    /// <param name="cancellationToken">Token for aborting administration storage work.</param>
    /// <returns>A list of safe bucket summaries.</returns>
    Task<IReadOnlyList<AuthenticationRateLimitBucketSummary>> SearchBucketsAsync(
        SearchAuthenticationRateLimitBucketsRequest request,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);

    /// <summary>Loads a safe summary for a single persisted authentication rate-limit bucket.</summary>
    /// <param name="request">Validated lookup request.</param>
    /// <param name="now">Current UTC time used for status projection.</param>
    /// <param name="cancellationToken">Token for aborting administration storage work.</param>
    /// <returns>The bucket summary when found; otherwise <see langword="null" />.</returns>
    Task<AuthenticationRateLimitBucketSummary?> GetBucketAsync(
        AuthenticationRateLimitBucketLookupRequest request,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);
}
