namespace Ashlar.Security.Tokens;

/// <summary>
/// Hashes high-entropy, server-generated tokens for deterministic storage lookup.
/// </summary>
public interface ISecureTokenHasher
{
    /// <summary>
    /// Hashes a raw token.
    /// </summary>
    /// <param name="token">The raw token to hash.</param>
    /// <returns>A deterministic token hash suitable for persistence.</returns>
    string HashToken(string token);
}
