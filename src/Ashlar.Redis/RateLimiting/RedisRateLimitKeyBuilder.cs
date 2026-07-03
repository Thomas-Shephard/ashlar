using System.Security.Cryptography;
using System.Text;

namespace Ashlar.Redis.RateLimiting;

internal static class RedisRateLimitKeyBuilder
{
    internal const int BucketIdLength = 64;

    internal static string Build(string prefix, string? purpose, string key)
    {
        var normalizedPurpose = purpose ?? string.Empty;
        var material = $"{normalizedPurpose.Length}:{normalizedPurpose}:{key}";
        var byteCount = Encoding.UTF8.GetByteCount(material);
        Span<byte> buffer = byteCount <= 256 ? stackalloc byte[byteCount] : new byte[byteCount];
        Encoding.UTF8.GetBytes(material, buffer);

        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(buffer, hash);

#if NET9_0_OR_GREATER
        var hex = Convert.ToHexStringLower(hash);
#else
        var hex = Convert.ToHexString(hash).ToLowerInvariant();
#endif
        return $"{NormalizePrefix(prefix)}:auth:{hex}";
    }

    internal static bool IsBucketId(string bucketId)
    {
        if (bucketId.Length != BucketIdLength)
        {
            return false;
        }

        foreach (var character in bucketId)
        {
            if (!IsLowerHex(character))
            {
                return false;
            }
        }

        return true;
    }

    internal static string NormalizePrefix(string prefix)
    {
        return prefix.TrimEnd(':');
    }

    private static bool IsLowerHex(char character)
    {
        return character is >= '0' and <= '9' or >= 'a' and <= 'f';
    }
}
