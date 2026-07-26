using System.Security.Cryptography;
using System.Text;
using Ashlar.Identity.RateLimiting.Abstractions;
using Dapper;
using Npgsql;

namespace Ashlar.Postgres.RateLimiting;

internal sealed class PostgresAuthenticationRateLimitAdministrationRepository(NpgsqlDataSource dataSource) : IAuthenticationRateLimitAdministrationRepository
{
    private readonly NpgsqlDataSource _dataSource = dataSource ?? throw new ArgumentNullException(nameof(dataSource));

    public async Task<IReadOnlyList<AuthenticationRateLimitBucketSummary>> SearchBucketsAsync(SearchAuthenticationRateLimitBucketsRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var sql = """
            SELECT rate_limit_key AS BucketId,
                   purpose AS Purpose,
                   count AS Count,
                   window_start AS WindowStart,
                   expires_at AS ExpiresAt,
                   blocked_until AS BlockedUntil
            FROM ashlar_rate_limits
            WHERE 1 = 1
            """;
        var parameters = new DynamicParameters();
        parameters.Add("now", now);
        AddFilters(request, parameters, ref sql);
        sql += " ORDER BY expires_at, purpose, rate_limit_key LIMIT @limit OFFSET @offset;";
        parameters.Add("limit", request.Limit);
        parameters.Add("offset", request.Offset);

        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        var rows = await connection.QueryAsync<Row>(new CommandDefinition(sql, parameters, cancellationToken: cancellationToken));
        return rows
            .Select(row => row.ToSummary(now))
            .ToList()
            .AsReadOnly();
    }

    public async Task<AuthenticationRateLimitBucketSummary?> GetBucketAsync(AuthenticationRateLimitBucketLookupRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        const string sql = """
            SELECT rate_limit_key AS BucketId,
                   purpose AS Purpose,
                   count AS Count,
                   window_start AS WindowStart,
                   expires_at AS ExpiresAt,
                   blocked_until AS BlockedUntil
            FROM ashlar_rate_limits
            WHERE purpose = @purpose;
            """;

        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        var rows = await connection.QueryAsync<Row>(new CommandDefinition(sql, new
        {
            purpose = request.Purpose
        }, cancellationToken: cancellationToken));

        return rows.Select(row => row.ToLookupResult(now, request.BucketId)).FirstOrDefault(bucket => bucket != null);
    }

    public async Task<bool> ResetBucketAsync(ResetAuthenticationRateLimitBucketRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        const string selectSql = """
            SELECT rate_limit_key
            FROM ashlar_rate_limits
            WHERE purpose = @purpose;
            """;

        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        var keys = await connection.QueryAsync<string>(new CommandDefinition(selectSql, new { purpose = request.Purpose }, cancellationToken: cancellationToken));
        var storedKey = keys.FirstOrDefault(key => string.Equals(ToBucketId(key), request.BucketId, StringComparison.Ordinal));
        if (storedKey == null)
        {
            return false;
        }

        const string sql = """
            DELETE FROM ashlar_rate_limits
            WHERE purpose = @purpose AND rate_limit_key = @bucketId;
            """;

        var deleted = await connection.ExecuteAsync(new CommandDefinition(sql, new
        {
            purpose = request.Purpose,
            bucketId = storedKey
        }, cancellationToken: cancellationToken));
        return deleted > 0;
    }

    private static void AddFilters(SearchAuthenticationRateLimitBucketsRequest request, DynamicParameters parameters, ref string sql)
    {
        if (request.Purpose != null)
        {
            sql += " AND purpose = @purpose";
            parameters.Add("purpose", request.Purpose);
        }

        AddRange(request.WindowStartFrom, request.WindowStartTo, "window_start", "windowStartFrom", "windowStartTo", parameters, ref sql);
        AddRange(request.ExpiresFrom, request.ExpiresTo, "expires_at", "expiresFrom", "expiresTo", parameters, ref sql);
        AddRange(request.BlockedUntilFrom, request.BlockedUntilTo, "blocked_until", "blockedUntilFrom", "blockedUntilTo", parameters, ref sql);

        if (request.Status == AuthenticationRateLimitBucketStatus.Blocked)
        {
            sql += " AND blocked_until IS NOT NULL AND blocked_until > @now";
        }
        else if (request.Status == AuthenticationRateLimitBucketStatus.Expired)
        {
            sql += " AND expires_at <= @now AND (blocked_until IS NULL OR blocked_until <= @now)";
        }
        else if (request.Status == AuthenticationRateLimitBucketStatus.Active)
        {
            sql += " AND expires_at > @now AND (blocked_until IS NULL OR blocked_until <= @now)";
        }
    }

    private static void AddRange(DateTimeOffset? from, DateTimeOffset? to, string column, string fromName, string toName, DynamicParameters parameters, ref string sql)
    {
        if (from.HasValue)
        {
            sql += $" AND {column} >= @{fromName}";
            parameters.Add(fromName, from.Value);
        }

        if (to.HasValue)
        {
            sql += $" AND {column} <= @{toName}";
            parameters.Add(toName, to.Value);
        }
    }

    private sealed record Row(
        string BucketId,
        string Purpose,
        int Count,
        DateTime WindowStart,
        DateTime ExpiresAt,
        DateTime? BlockedUntil)
    {
        public AuthenticationRateLimitBucketSummary ToSummary(DateTimeOffset now)
        {
            return new AuthenticationRateLimitBucketSummary(ToBucketId(BucketId), Purpose, Count, ToDateTimeOffset(WindowStart), ToDateTimeOffset(ExpiresAt), ToNullableDateTimeOffset(BlockedUntil), DeriveStatus(now));
        }

        public AuthenticationRateLimitBucketSummary? ToLookupResult(DateTimeOffset now, string requestedBucketId)
        {
            var bucketId = ToBucketId(BucketId);
            return string.Equals(bucketId, requestedBucketId, StringComparison.Ordinal)
                ? new AuthenticationRateLimitBucketSummary(bucketId, Purpose, Count, ToDateTimeOffset(WindowStart), ToDateTimeOffset(ExpiresAt), ToNullableDateTimeOffset(BlockedUntil), DeriveStatus(now))
                : null;
        }

        private AuthenticationRateLimitBucketStatus DeriveStatus(DateTimeOffset now)
        {
            var blockedUntil = ToNullableDateTimeOffset(BlockedUntil);
            if (blockedUntil.HasValue && blockedUntil.Value > now)
            {
                return AuthenticationRateLimitBucketStatus.Blocked;
            }

            return ToDateTimeOffset(ExpiresAt) <= now
                ? AuthenticationRateLimitBucketStatus.Expired
                : AuthenticationRateLimitBucketStatus.Active;
        }

        private static DateTimeOffset ToDateTimeOffset(DateTime value)
        {
            return new DateTimeOffset(DateTime.SpecifyKind(value, DateTimeKind.Utc));
        }

        private static DateTimeOffset? ToNullableDateTimeOffset(DateTime? value)
        {
            return value.HasValue ? ToDateTimeOffset(value.Value) : null;
        }
    }

    private static string ToBucketId(string storedKey)
    {
        var bytes = Encoding.UTF8.GetBytes(storedKey);
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(bytes, hash);
#if NET9_0_OR_GREATER
        return Convert.ToHexStringLower(hash);
#else
        return Convert.ToHexString(hash).ToLowerInvariant();
#endif
    }
}
