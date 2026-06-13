using System.Security.Cryptography;

namespace Ashlar.Security.Tokens;

/// <summary>
/// Generates high-entropy URL-safe tokens using a cryptographic random number generator.
/// </summary>
public sealed class SecureTokenGenerator : ISecureTokenGenerator
{
    /// <summary>
    /// Generates a URL-safe raw bearer token.
    /// </summary>
    /// <param name="byteLength">The number of random bytes to encode.</param>
    /// <returns>A raw token value. Return it only to the intended recipient and store only a hash when possible.</returns>
    public string GenerateToken(int byteLength = ISecureTokenGenerator.DefaultByteLength)
    {
        if (byteLength is < ISecureTokenGenerator.MinimumByteLength or > ISecureTokenGenerator.MaximumByteLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(byteLength),
                byteLength,
                $"Security tokens must be between {ISecureTokenGenerator.MinimumByteLength} and {ISecureTokenGenerator.MaximumByteLength} bytes to remain compatible with the default token pipeline.");
        }

        var bytes = RandomNumberGenerator.GetBytes(byteLength);
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
