namespace Ashlar.Security.Tokens;

/// <summary>
/// Provides safe token hashing helpers for public token lookup paths.
/// </summary>
public static class SecureTokenHashing
{
    /// <summary>
    /// Attempts to hash a caller-supplied token without surfacing token validation exceptions.
    /// </summary>
    /// <param name="hasher">The token hasher.</param>
    /// <param name="token">The caller-supplied token.</param>
    /// <param name="tokenHash">The hashed token when hashing succeeds.</param>
    /// <returns><see langword="true" /> when the token was hashed; otherwise, <see langword="false" />.</returns>
    public static bool TryHashToken(ISecureTokenHasher hasher, string token, out string tokenHash)
    {
        ArgumentNullException.ThrowIfNull(hasher);

        try
        {
            tokenHash = hasher.HashToken(token);
            return true;
        }
        catch (ArgumentException)
        {
            tokenHash = string.Empty;
            return false;
        }
    }
}
