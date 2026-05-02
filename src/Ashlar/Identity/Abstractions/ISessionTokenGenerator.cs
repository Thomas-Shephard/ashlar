namespace Ashlar.Identity.Abstractions;

/// <summary>
/// Generates high-entropy raw authentication session tokens.
/// </summary>
public interface ISessionTokenGenerator
{
    /// <summary>
    /// Generates a URL- and cookie-safe raw session token.
    /// </summary>
    /// <param name="byteLength">The number of random bytes to encode.</param>
    /// <returns>A raw session token. This value should only be returned to the caller at creation time.</returns>
    string GenerateToken(int byteLength);
}
