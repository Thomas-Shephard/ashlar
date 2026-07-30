using Ashlar.Auditing;

namespace Ashlar.Identity.Models.Administration;

/// <summary>
/// Operational status for an authentication rate-limit bucket.
/// </summary>
public enum AuthenticationRateLimitBucketStatus
{
    /// <summary>
    /// The bucket window is active and is not currently blocking attempts.
    /// </summary>
    Active = 0,

    /// <summary>
    /// The bucket has expired and no longer affects authentication attempts.
    /// </summary>
    Expired = 1,

    /// <summary>
    /// The bucket is currently blocking authentication attempts.
    /// </summary>
    Blocked = 2
}

/// <summary>
/// Reset outcome for an authentication rate-limit bucket operation.
/// </summary>
public enum AuthenticationRateLimitBucketResetStatus
{
    /// <summary>
    /// The selected bucket was reset.
    /// </summary>
    Reset = 0,

    /// <summary>
    /// No matching bucket was found.
    /// </summary>
    NotFound = 1,

    /// <summary>
    /// The provider failed to reset the selected bucket.
    /// </summary>
    Failed = 2
}

/// <summary>
/// Request for administrator authentication rate-limit bucket search.
/// </summary>
/// <remarks>
/// The administration reader enforces actor session, proof, scope, and host authorization before executing this operation.
/// Bucket identifiers are opaque operational identifiers derived from stored hashed key material.
/// </remarks>
public sealed record SearchAuthenticationRateLimitBucketsRequest
{
    /// <summary>Optional purpose filter. Purpose values are provider-neutral flow labels, not raw user inputs.</summary>
    public string? Purpose { get; init; }

    /// <summary>Optional projected status filter.</summary>
    public AuthenticationRateLimitBucketStatus? Status { get; init; }

    /// <summary>Inclusive lower window-start time bound.</summary>
    public DateTimeOffset? WindowStartFrom { get; init; }

    /// <summary>Inclusive upper window-start time bound.</summary>
    public DateTimeOffset? WindowStartTo { get; init; }

    /// <summary>Inclusive lower expiration time bound.</summary>
    public DateTimeOffset? ExpiresFrom { get; init; }

    /// <summary>Inclusive upper expiration time bound.</summary>
    public DateTimeOffset? ExpiresTo { get; init; }

    /// <summary>Inclusive lower blocked-until time bound.</summary>
    public DateTimeOffset? BlockedUntilFrom { get; init; }

    /// <summary>Inclusive upper blocked-until time bound.</summary>
    public DateTimeOffset? BlockedUntilTo { get; init; }

    /// <summary>
    /// Maximum number of buckets to return. The administration service caps requests at 100 buckets per page.
    /// </summary>
    public int Limit { get; init; } = 50;

    /// <summary>Number of matching buckets to skip.</summary>
    public int Offset { get; init; }

    /// <summary>
    /// Throws when the bucket search request is not safe to execute.
    /// </summary>
    /// <param name="request">Search request to validate before querying administration data.</param>
    public static void ThrowIfInvalid(SearchAuthenticationRateLimitBucketsRequest? request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Purpose is { Length: 0 })
        {
            throw new ArgumentException("Purpose cannot be empty.", nameof(request));
        }
    }
}

/// <summary>
/// Safe summary of an authentication rate-limit bucket for administrator display.
/// </summary>
/// <param name="BucketId">Opaque operational bucket identifier derived from stored hashed key material.</param>
/// <param name="Purpose">Provider-neutral purpose recorded for the bucket.</param>
/// <param name="Count">Number of attempts currently recorded in the bucket.</param>
/// <param name="WindowStart">UTC time when the current bucket window started.</param>
/// <param name="ExpiresAt">UTC time after which the bucket no longer affects authentication attempts.</param>
/// <param name="BlockedUntil">UTC time until which attempts are blocked, when currently blocked or recently blocked.</param>
/// <param name="Status">Projected bucket status at query time.</param>
public sealed record AuthenticationRateLimitBucketSummary(
    string BucketId,
    string Purpose,
    int Count,
    DateTimeOffset WindowStart,
    DateTimeOffset ExpiresAt,
    DateTimeOffset? BlockedUntil,
    AuthenticationRateLimitBucketStatus Status);

/// <summary>
/// Authentication bucket search page for administrator display.
/// </summary>
/// <param name="Items">Page of display-safe bucket summaries.</param>
/// <param name="Limit">Maximum page size requested for the result.</param>
/// <param name="Offset">Number of matching buckets skipped before this page.</param>
/// <param name="HasMore">Whether another page may exist. Concurrent key changes can affect Redis-backed page exactness.</param>
public sealed record AuthenticationRateLimitBucketSearchResult(
    IReadOnlyList<AuthenticationRateLimitBucketSummary> Items,
    int Limit,
    int Offset,
    bool HasMore);

/// <summary>
/// Request for administrator authentication rate-limit bucket lookup.
/// </summary>
/// <param name="BucketId">Opaque bucket identifier returned by search.</param>
/// <param name="Purpose">Purpose that scopes the bucket identifier.</param>
public sealed record AuthenticationRateLimitBucketLookupRequest(string BucketId, string Purpose)
{
    /// <summary>
    /// Throws when the bucket lookup request is not safe to execute.
    /// </summary>
    /// <param name="request">Lookup request to validate before loading administrator data.</param>
    public static void ThrowIfInvalid(AuthenticationRateLimitBucketLookupRequest? request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.BucketId);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Purpose);
    }
}

/// <summary>
/// Request for resetting a selected authentication rate-limit bucket.
/// </summary>
/// <param name="BucketId">Opaque bucket identifier returned by search.</param>
/// <param name="Purpose">Purpose that scopes the bucket identifier.</param>
/// <param name="Audit">Required audit context for the operator or calling workflow.</param>
/// <remarks>
/// The administration service enforces actor session, proof, scope, host authorization, and durable security-event recording before executing this operation.
/// </remarks>
public sealed record ResetAuthenticationRateLimitBucketRequest(string BucketId, string Purpose, AuditContext Audit)
{
    /// <summary>
    /// Throws when the bucket reset request is not safe to execute.
    /// </summary>
    /// <param name="request">Reset request to validate before deleting administration data.</param>
    public static void ThrowIfInvalid(ResetAuthenticationRateLimitBucketRequest? request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.BucketId);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Purpose);
        ArgumentNullException.ThrowIfNull(request.Audit);
    }
}

/// <summary>
/// Result of a selected authentication rate-limit bucket reset.
/// </summary>
/// <param name="BucketId">Opaque bucket identifier supplied by the reset request.</param>
/// <param name="Purpose">Purpose supplied by the reset request.</param>
/// <param name="Status">Stable reset outcome.</param>
public sealed record AuthenticationRateLimitBucketResetResult(
    string BucketId,
    string Purpose,
    AuthenticationRateLimitBucketResetStatus Status);
