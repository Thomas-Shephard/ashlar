namespace Ashlar.Identity.RateLimiting.Abstractions;

/// <summary>
/// Provides safe global operational administrator operations for resetting authentication rate-limit buckets.
/// </summary>
/// <remarks>
/// Bucket identifiers returned by this service are opaque operational identifiers derived from stored hashed keys.
/// They are not raw rate-limit inputs and must not be treated as IP addresses, email addresses, user identifiers, tokens, or Redis key names.
/// Operations require an active actor session, fresh administration proof, explicit global operational scope, all-tenant host authorization, and durable audit.
/// Tenant-scoped administration is not exposed because rate-limit administration repositories do not store tenant ownership.
/// The service is registered by provider-backed rate limiter packages that support administration; the default in-memory limiter does not expose an administration implementation.
/// Searches are capped at 100 buckets per page. Redis-backed searches use a bounded key scan, so paging can be approximate while Redis keys change concurrently.
/// Use <see cref="IAuthenticationRateLimitAdministrationReader" /> for browsing operations.
/// </remarks>
public interface IAuthenticationRateLimitAdministrationService
{
    /// <summary>
    /// Resets a selected authentication rate-limit bucket.
    /// </summary>
    /// <param name="actor">Authenticated administrator context.</param>
    /// <param name="scope">Explicit global operational scope.</param>
    /// <param name="request">Reset request containing the bucket identifier, purpose, and audit context.</param>
    /// <param name="cancellationToken">Token for aborting administration storage work.</param>
    /// <returns>A result describing whether the selected bucket was reset.</returns>
    Task<Result<AuthenticationRateLimitBucketResetResult>> ResetBucketAsync(AccountSecurityActorContext actor, AuthenticationRateLimitAdministrationScope scope, ResetAuthenticationRateLimitBucketRequest request, CancellationToken cancellationToken = default);
}
