namespace Ashlar.Security.Tokens;

/// <summary>
/// Generates high-entropy, server-side security tokens.
/// </summary>
public interface ISecureTokenGenerator
{
    /// <summary>
    /// The default number of random bytes used for generated tokens.
    /// </summary>
    public const int DefaultByteLength = 32;
    /// <summary>
    /// The minimum supported random byte length.
    /// </summary>
    public const int MinimumByteLength = 32;
    /// <summary>
    /// The maximum supported random byte length.
    /// </summary>
    public const int MaximumByteLength = 192;

    /// <summary>
    /// Generates a URL-safe raw token from the requested number of random bytes.
    /// </summary>
    /// <param name="byteLength">The amount of random entropy to include before URL-safe encoding.</param>
    /// <returns>A bearer token value. Display it only to the intended recipient and store only a hash when possible.</returns>
    string GenerateToken(int byteLength = DefaultByteLength);
}
