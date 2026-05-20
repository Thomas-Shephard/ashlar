using System.Security.Cryptography;

namespace Ashlar.Security.Tokens;

/// <summary>
/// Generates high-entropy URL-safe tokens using a cryptographic random number generator.
/// </summary>
public sealed class SecureTokenGenerator : ISecureTokenGenerator
{
    /// <summary>
    /// Performs the generate token operation and returns the result.
    /// </summary>
    /// <param name="byteLength">The byte length value.</param>
    /// <returns>The operation result.</returns>
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


