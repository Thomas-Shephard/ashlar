using System.Security.Cryptography;
using System.Text;
using Ashlar.Identity.RateLimiting.Abstractions;

namespace Ashlar.Sqlite.RateLimiting;

internal sealed class SqliteAuthenticationRateLimitAdministrationRepository(ISqliteConnectionProvider connectionProvider) : IAuthenticationRateLimitAdministrationRepository
{
    private const string PurposeParameterName = "$purpose";

    private readonly ISqliteConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));

    public async Task<IReadOnlyList<AuthenticationRateLimitBucketSummary>> SearchBucketsAsync(SearchAuthenticationRateLimitBucketsRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var sql = """
            SELECT rate_limit_key,
                   purpose,
                   count,
                   window_start,
                   expires_at,
                   blocked_until
            FROM ashlar_rate_limits
            WHERE 1 = 1
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.AddDateTimeOffsetParameter("$now", now);
        AddFilters(command, request, ref sql);
        sql += " ORDER BY expires_at, purpose, rate_limit_key LIMIT $limit OFFSET $offset;";
        command.CommandText = sql;
        command.AddParameter("$limit", request.Limit);
        command.AddParameter("$offset", request.Offset);

        var buckets = new List<AuthenticationRateLimitBucketSummary>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var row = ReadRow(reader);
            buckets.Add(row.ToSummary(now));
        }

        return buckets.AsReadOnly();
    }

    public async Task<AuthenticationRateLimitBucketSummary?> GetBucketAsync(AuthenticationRateLimitBucketLookupRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        const string sql = """
            SELECT rate_limit_key,
                   purpose,
                   count,
                   window_start,
                   expires_at,
                   blocked_until
            FROM ashlar_rate_limits
            WHERE purpose = $purpose;
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddParameter(PurposeParameterName, request.Purpose);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var bucket = ReadRow(reader).ToLookupResult(now, request.BucketId);
            if (bucket != null)
            {
                return bucket;
            }
        }

        return null;
    }

    public async Task<bool> ResetBucketAsync(ResetAuthenticationRateLimitBucketRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var storedKey = await FindStoredKeyAsync(request.Purpose, request.BucketId, cancellationToken);
        if (storedKey == null)
        {
            return false;
        }

        const string sql = """
            DELETE FROM ashlar_rate_limits
            WHERE purpose = $purpose AND rate_limit_key = $bucketId;
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddParameter(PurposeParameterName, request.Purpose);
        command.AddParameter("$bucketId", storedKey);

        return await command.ExecuteNonQueryAsync(cancellationToken) > 0;
    }

    private async Task<string?> FindStoredKeyAsync(string purpose, string bucketId, CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT rate_limit_key
            FROM ashlar_rate_limits
            WHERE purpose = $purpose;
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddParameter(PurposeParameterName, purpose);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var storedKey = reader.GetString(0);
            if (string.Equals(ToBucketId(storedKey), bucketId, StringComparison.Ordinal))
            {
                return storedKey;
            }
        }

        return null;
    }

    private static void AddFilters(Microsoft.Data.Sqlite.SqliteCommand command, SearchAuthenticationRateLimitBucketsRequest request, ref string sql)
    {
        if (request.Purpose != null)
        {
            sql += " AND purpose = $purpose";
            command.AddParameter(PurposeParameterName, request.Purpose);
        }

        command.AddDateRange(request.WindowStartFrom, request.WindowStartTo, "window_start", "$windowStartFrom", "$windowStartTo", ref sql);
        command.AddDateRange(request.ExpiresFrom, request.ExpiresTo, "expires_at", "$expiresFrom", "$expiresTo", ref sql);
        command.AddDateRange(request.BlockedUntilFrom, request.BlockedUntilTo, "blocked_until", "$blockedUntilFrom", "$blockedUntilTo", ref sql);

        if (request.Status == AuthenticationRateLimitBucketStatus.Blocked)
        {
            sql += " AND blocked_until IS NOT NULL AND blocked_until > $now";
        }
        else if (request.Status == AuthenticationRateLimitBucketStatus.Expired)
        {
            sql += " AND expires_at <= $now AND (blocked_until IS NULL OR blocked_until <= $now)";
        }
        else if (request.Status == AuthenticationRateLimitBucketStatus.Active)
        {
            sql += " AND expires_at > $now AND (blocked_until IS NULL OR blocked_until <= $now)";
        }
    }

    private static Row ReadRow(Microsoft.Data.Sqlite.SqliteDataReader reader)
    {
        return new Row(
            reader.GetString(reader.GetOrdinal("rate_limit_key")),
            reader.GetString(reader.GetOrdinal("purpose")),
            reader.GetInt32ByName("count"),
            reader.GetDateTimeOffsetFromText("window_start"),
            reader.GetDateTimeOffsetFromText("expires_at"),
            reader.GetNullableDateTimeOffsetFromText("blocked_until"));
    }

    private sealed record Row(
        string BucketId,
        string Purpose,
        int Count,
        DateTimeOffset WindowStart,
        DateTimeOffset ExpiresAt,
        DateTimeOffset? BlockedUntil)
    {
        public AuthenticationRateLimitBucketSummary ToSummary(DateTimeOffset now)
        {
            return new AuthenticationRateLimitBucketSummary(ToBucketId(BucketId), Purpose, Count, WindowStart, ExpiresAt, BlockedUntil, DeriveStatus(now));
        }

        public AuthenticationRateLimitBucketSummary? ToLookupResult(DateTimeOffset now, string requestedBucketId)
        {
            var bucketId = ToBucketId(BucketId);
            return string.Equals(bucketId, requestedBucketId, StringComparison.Ordinal)
                ? new AuthenticationRateLimitBucketSummary(bucketId, Purpose, Count, WindowStart, ExpiresAt, BlockedUntil, DeriveStatus(now))
                : null;
        }

        private AuthenticationRateLimitBucketStatus DeriveStatus(DateTimeOffset now)
        {
            if (BlockedUntil.HasValue && BlockedUntil.Value > now)
            {
                return AuthenticationRateLimitBucketStatus.Blocked;
            }

            return ExpiresAt <= now
                ? AuthenticationRateLimitBucketStatus.Expired
                : AuthenticationRateLimitBucketStatus.Active;
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
