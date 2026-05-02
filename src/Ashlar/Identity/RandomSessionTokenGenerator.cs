using System.Security.Cryptography;
using Ashlar.Identity.Abstractions;

namespace Ashlar.Identity;

/// <summary>
/// Generates high-entropy URL- and cookie-safe session tokens.
/// </summary>
public sealed class RandomSessionTokenGenerator : ISessionTokenGenerator
{
    public string GenerateToken(int byteLength)
    {
        if (byteLength < 32)
        {
            throw new ArgumentOutOfRangeException(nameof(byteLength), byteLength, "Session tokens require at least 32 bytes of entropy.");
        }

        var bytes = RandomNumberGenerator.GetBytes(byteLength);
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
