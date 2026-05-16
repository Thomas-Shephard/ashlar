namespace Ashlar.Security.Tokens;

/// <summary>
/// Hashes high-entropy, server-generated tokens for deterministic storage lookup.
/// </summary>
public interface ISecureTokenHasher
{
    /// <summary>
    /// Hashes a raw token.
    /// </summary>
    /// <param name="token">The token value.</param>
    /// <returns>The operation result.</returns>
    string HashToken(string token);
}
