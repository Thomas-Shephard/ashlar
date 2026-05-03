namespace Ashlar.Security.Tokens;

/// <summary>
/// Generates high-entropy, server-side security tokens.
/// </summary>
public interface ISecureTokenGenerator
{
    public const int DefaultByteLength = 32;
    public const int MinimumByteLength = 32;
    public const int MaximumByteLength = 192;

    /// <summary>
    /// Generates a URL-safe token from the requested number of random bytes.
    /// </summary>
    /// <param name="byteLength">The number of random bytes to encode. Must be between 32 and 192.</param>
    /// <returns>A raw token that should only be returned to the caller when issued.</returns>
    string GenerateToken(int byteLength = DefaultByteLength);
}
