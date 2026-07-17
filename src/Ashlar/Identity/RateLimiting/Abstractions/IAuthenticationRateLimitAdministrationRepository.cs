namespace Ashlar.Identity.RateLimiting.Abstractions;

/// <summary>
/// Provider storage abstraction for safe authentication rate-limit administration operations.
/// </summary>
public interface IAuthenticationRateLimitAdministrationRepository : IAuthenticationRateLimitAdministrationReaderRepository
{
    /// <summary>
    /// Deletes a selected authentication rate-limit bucket.
    /// </summary>
    /// <param name="request">Validated reset request.</param>
    /// <param name="cancellationToken">Token for aborting administration storage work.</param>
    /// <returns><see langword="true" /> when a bucket was deleted; otherwise <see langword="false" />.</returns>
    Task<bool> ResetBucketAsync(ResetAuthenticationRateLimitBucketRequest request, CancellationToken cancellationToken = default);
}
