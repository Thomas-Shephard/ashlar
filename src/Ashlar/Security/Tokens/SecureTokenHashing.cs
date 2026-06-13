using System.Diagnostics.CodeAnalysis;

namespace Ashlar.Security.Tokens;

/// <summary>
/// Provides safe token hashing helpers for public token lookup paths.
/// </summary>
public static class SecureTokenHashing
{
    /// <summary>
    /// Attempts to hash a caller-supplied token without surfacing token validation exceptions.
    /// </summary>
    /// <param name="hasher">Hasher used to derive the storage lookup value.</param>
    /// <param name="token">The raw caller-supplied bearer token. Do not log or persist this value.</param>
    /// <param name="tokenHash">The storage lookup hash when hashing succeeds; otherwise, an empty string.</param>
    /// <returns><see langword="true" /> when the token was hashed; otherwise, <see langword="false" />.</returns>
    public static bool TryHashToken(ISecureTokenHasher hasher, [NotNullWhen(true)] string? token, out string tokenHash)
    {
        ArgumentNullException.ThrowIfNull(hasher);

        if (string.IsNullOrWhiteSpace(token))
        {
            tokenHash = string.Empty;
            return false;
        }

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
