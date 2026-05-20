namespace Ashlar.Security.Tokens;

/// <summary>
/// Generates high-entropy, server-side security tokens.
/// </summary>
public interface ISecureTokenGenerator
{
    /// <summary>
    /// Defines the default byte length value.
    /// </summary>
    public const int DefaultByteLength = 32;
    /// <summary>
    /// Defines the minimum byte length value.
    /// </summary>
    public const int MinimumByteLength = 32;
    /// <summary>
    /// Defines the maximum byte length value.
    /// </summary>
    public const int MaximumByteLength = 192;

    /// <summary>
    /// Generates a URL-safe token from the requested number of random bytes.
    /// </summary>
    /// <param name="byteLength">The byte length value.</param>
    /// <returns>The operation result.</returns>
    string GenerateToken(int byteLength = DefaultByteLength);
}
