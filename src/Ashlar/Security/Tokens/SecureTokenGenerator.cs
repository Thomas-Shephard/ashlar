using System.Security.Cryptography;

namespace Ashlar.Security.Tokens;

/// <summary>
/// Generates high-entropy URL-safe tokens using a cryptographic random number generator.
/// </summary>
public sealed class SecureTokenGenerator : ISecureTokenGenerator
{
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
