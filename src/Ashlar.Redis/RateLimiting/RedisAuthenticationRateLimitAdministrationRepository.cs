using Ashlar.Identity.Models.Administration;
using Ashlar.Identity.RateLimiting.Abstractions;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace Ashlar.Redis.RateLimiting;

internal sealed class RedisAuthenticationRateLimitAdministrationRepository : IAuthenticationRateLimitAdministrationReaderRepository
{
    internal const int MaximumScanCount = 1000;

    private readonly Func<ValueTask<IConnectionMultiplexer>> _getConnectionAsync;
    private readonly RedisAuthenticationRateLimiterOptions _options;

    internal RedisAuthenticationRateLimitAdministrationRepository(IConnectionMultiplexer connection, IOptions<RedisAuthenticationRateLimiterOptions> options)
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
