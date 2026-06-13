namespace Ashlar.Security.Hashing;

/// <summary>
/// Hashes and verifies user-chosen passwords.
/// </summary>
public interface IPasswordHasher
{
    /// <summary>
    /// Number of bytes reserved for the hash format version.
    /// </summary>
    public const int VersionLength = 1;
    /// <summary>
    /// Hash format version produced by this hasher.
    /// </summary>
    byte Version { get; }
    /// <summary>
    /// Hashes a plaintext password for credential storage.
    /// </summary>
    /// <param name="password">The plaintext password. Do not log this value.</param>
    /// <returns>An encoded password hash suitable for storage.</returns>
    byte[] HashPassword(ReadOnlySpan<char> password);
    /// <summary>
    /// Verifies a plaintext password against an encoded hash.
    /// </summary>
    /// <param name="password">The plaintext password. Do not log this value.</param>
    /// <param name="encodedHash">The stored encoded hash.</param>
    /// <returns><see langword="true" /> when the password matches the hash.</returns>
    bool VerifyPassword(ReadOnlySpan<char> password, ReadOnlySpan<byte> encodedHash);
}
