using Ashlar.Identity.Models.Administration;
using Ashlar.Identity.RateLimiting.Abstractions;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace Ashlar.Redis.RateLimiting;

/// <summary>
/// Redis-backed authentication rate-limit administration repository using a bounded key scan.
/// </summary>
/// <remarks>
/// Search uses Redis SCAN over the configured Ashlar rate-limit prefix and returns only opaque hash suffixes, never physical Redis key names.
/// Exact paging can vary while Redis keys are changing concurrently.
/// </remarks>
public sealed class RedisAuthenticationRateLimitAdministrationRepository : IAuthenticationRateLimitAdministrationRepository
{
    internal const int MaximumScanCount = 1000;

    private readonly Func<ValueTask<IConnectionMultiplexer>> _getConnectionAsync;
    private readonly RedisAuthenticationRateLimiterOptions _options;

    /// <summary>
    /// Initializes a Redis-backed authentication rate-limit administration repository.
    /// </summary>
    /// <param name="connection">The Redis connection multiplexer.</param>
    /// <param name="options">The Redis rate limiter options.</param>
    public RedisAuthenticationRateLimitAdministrationRepository(IConnectionMultiplexer connection, IOptions<RedisAuthenticationRateLimiterOptions> options)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(options);

        _getConnectionAsync = () => ValueTask.FromResult(connection);
        _options = options.Value;
        ValidateOptions(options);
    }

    internal RedisAuthenticationRateLimitAdministrationRepository(RedisAuthenticationRateLimiterConnection connectionWrapper, IOptions<RedisAuthenticationRateLimiterOptions> options)
    {
        ArgumentNullException.ThrowIfNull(connectionWrapper);
        ArgumentNullException.ThrowIfNull(options);

        _getConnectionAsync = connectionWrapper.GetConnectionAsync;
        _options = options.Value;
        ValidateOptions(options);
    }

    /// <summary>
    /// Searches Redis rate-limit buckets without exposing raw key material or configured Redis key prefixes.
    /// </summary>
    /// <param name="request">Validated search request.</param>
    /// <param name="now">Current UTC time used for status projection.</param>
    /// <param name="cancellationToken">Token for aborting Redis work.</param>
    /// <returns>A list of safe bucket summaries discovered by the bounded scan.</returns>
    public async Task<IReadOnlyList<AuthenticationRateLimitBucketSummary>> SearchBucketsAsync(SearchAuthenticationRateLimitBucketsRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        var connection = await _getConnectionAsync();
        var database = connection.GetDatabase(_options.Database ?? -1);
        var prefix = RedisRateLimitKeyBuilder.NormalizePrefix(_options.KeyPrefix);
        var pattern = $"{prefix}:auth:*";
        var rows = new List<AuthenticationRateLimitBucketSummary>();
        var scanned = 0;

        foreach (var endpoint in connection.GetEndPoints())
        {
            var server = connection.GetServer(endpoint);
            foreach (var key in server.Keys(_options.Database ?? -1, pattern, pageSize: 250))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (++scanned > MaximumScanCount)
                {
                    break;
                }

                var row = await ReadBucketAsync(database, key, prefix, now);
                if (row != null && Matches(request, row))
                {
                    rows.Add(row);
                }
            }

            if (scanned > MaximumScanCount)
            {
                break;
            }
        }

        return rows
            .OrderBy(row => row.ExpiresAt)
            .ThenBy(row => row.Purpose, StringComparer.Ordinal)
            .ThenBy(row => row.BucketId, StringComparer.Ordinal)
            .Skip(request.Offset)
            .Take(request.Limit)
            .ToList()
            .AsReadOnly();
    }

    /// <summary>
    /// Loads a Redis rate-limit bucket by purpose and opaque bucket identifier.
    /// </summary>
    /// <param name="request">Validated lookup request.</param>
    /// <param name="now">Current UTC time used for status projection.</param>
    /// <param name="cancellationToken">Token for aborting Redis work.</param>
    /// <returns>The safe bucket summary when found; otherwise <see langword="null" />.</returns>
    public async Task<AuthenticationRateLimitBucketSummary?> GetBucketAsync(AuthenticationRateLimitBucketLookupRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        if (!RedisRateLimitKeyBuilder.IsBucketId(request.BucketId))
        {
            return null;
        }

        var connection = await _getConnectionAsync();
        var database = connection.GetDatabase(_options.Database ?? -1);
        var key = BuildPhysicalKey(request.BucketId);
        var row = await ReadBucketAsync(database, key, RedisRateLimitKeyBuilder.NormalizePrefix(_options.KeyPrefix), now);
        if (row == null || !string.Equals(row.Purpose, request.Purpose, StringComparison.Ordinal))
        {
            return null;
        }

        return row;
    }

    /// <summary>
    /// Deletes a Redis rate-limit bucket after verifying its stored purpose.
    /// </summary>
    /// <param name="request">Validated reset request.</param>
    /// <param name="cancellationToken">Token for aborting Redis work.</param>
    /// <returns><see langword="true" /> when a bucket was deleted; otherwise <see langword="false" />.</returns>
    public async Task<bool> ResetBucketAsync(ResetAuthenticationRateLimitBucketRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        if (!RedisRateLimitKeyBuilder.IsBucketId(request.BucketId))
        {
            return false;
        }

        var connection = await _getConnectionAsync();
        var database = connection.GetDatabase(_options.Database ?? -1);
        var key = BuildPhysicalKey(request.BucketId);
        var purpose = await database.HashGetAsync(key, "purpose");
        if (!purpose.HasValue || !string.Equals(purpose.ToString(), request.Purpose, StringComparison.Ordinal))
        {
            return false;
        }

        return await database.KeyDeleteAsync(key);
    }

    private RedisKey BuildPhysicalKey(string bucketId)
    {
        return (RedisKey)$"{RedisRateLimitKeyBuilder.NormalizePrefix(_options.KeyPrefix)}:auth:{bucketId}";
    }

    private static void ValidateOptions(IOptions<RedisAuthenticationRateLimiterOptions> options)
    {
        if (!RedisAuthenticationRateLimiterOptions.Validate(options.Value))
        {
            throw new ArgumentException("Redis rate limiter options are invalid.", nameof(options));
        }
    }

    private static async Task<AuthenticationRateLimitBucketSummary?> ReadBucketAsync(IDatabase database, RedisKey key, string prefix, DateTimeOffset now)
    {
        var keyText = key.ToString();
        var expectedPrefix = $"{prefix}:auth:";
        var bucketId = keyText[expectedPrefix.Length..];
        if (!RedisRateLimitKeyBuilder.IsBucketId(bucketId))
        {
            return null;
        }

        var values = await database.HashGetAsync(key, ["purpose", "count", "windowStart", "expiresAt", "blockedUntil"]);
        if (!values[0].HasValue || !values[1].HasValue || !values[2].HasValue || !values[3].HasValue)
        {
            return null;
        }

        var purpose = values[0].ToString();
        var count = (int)values[1];
        var windowStart = DateTimeOffset.FromUnixTimeMilliseconds((long)values[2]);
        var expiresAt = DateTimeOffset.FromUnixTimeMilliseconds((long)values[3]);
        var blockedUntil = values[4].HasValue ? DateTimeOffset.FromUnixTimeMilliseconds((long)values[4]) : (DateTimeOffset?)null;
        var status = DeriveStatus(expiresAt, blockedUntil, now);

        return new AuthenticationRateLimitBucketSummary(
            bucketId,
            purpose,
            count,
            windowStart,
            expiresAt,
            blockedUntil,
            status);
    }

    private static bool Matches(SearchAuthenticationRateLimitBucketsRequest request, AuthenticationRateLimitBucketSummary bucket)
    {
        if (request.Purpose != null && !string.Equals(bucket.Purpose, request.Purpose, StringComparison.Ordinal))
        {
            return false;
        }

        return (!request.Status.HasValue || bucket.Status == request.Status.Value)
            && IsInRange(bucket.WindowStart, request.WindowStartFrom, request.WindowStartTo)
            && IsInRange(bucket.ExpiresAt, request.ExpiresFrom, request.ExpiresTo)
            && IsNullableInRange(bucket.BlockedUntil, request.BlockedUntilFrom, request.BlockedUntilTo);
    }

    private static bool IsInRange(DateTimeOffset value, DateTimeOffset? from, DateTimeOffset? to)
    {
        return (!from.HasValue || value >= from.Value) && (!to.HasValue || value <= to.Value);
    }

    private static bool IsNullableInRange(DateTimeOffset? value, DateTimeOffset? from, DateTimeOffset? to)
    {
        if (!from.HasValue && !to.HasValue)
        {
            return true;
        }

        return value.HasValue && IsInRange(value.Value, from, to);
    }

    private static AuthenticationRateLimitBucketStatus DeriveStatus(DateTimeOffset expiresAt, DateTimeOffset? blockedUntil, DateTimeOffset now)
    {
        if (blockedUntil.HasValue && blockedUntil.Value > now)
        {
            return AuthenticationRateLimitBucketStatus.Blocked;
        }

        return expiresAt <= now
            ? AuthenticationRateLimitBucketStatus.Expired
            : AuthenticationRateLimitBucketStatus.Active;
    }
}
