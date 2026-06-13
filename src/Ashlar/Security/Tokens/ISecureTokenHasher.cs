namespace Ashlar.Security.Tokens;

/// <summary>
/// Hashes high-entropy, server-generated tokens for deterministic storage lookup.
/// </summary>
public interface ISecureTokenHasher
{
    /// <summary>
    /// Hashes a raw token for deterministic lookup without storing the bearer value.
    /// </summary>
    /// <param name="token">The raw token presented by a caller. Do not log or persist this value.</param>
    /// <returns>A storage-safe hash for equality lookup. The hash is not a substitute for the raw token.</returns>
    string HashToken(string token);
}
