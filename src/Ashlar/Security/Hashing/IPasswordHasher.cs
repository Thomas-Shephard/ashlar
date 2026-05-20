namespace Ashlar.Security.Hashing;

/// <summary>
/// Defines the contract for ipassword hasher operations.
/// </summary>
public interface IPasswordHasher
{
    /// <summary>
    /// Defines the version length value.
    /// </summary>
    public const int VersionLength = 1;
    /// <summary>
    /// Gets the version value.
    /// </summary>
    byte Version { get; }
    /// <summary>
    /// Performs the hash password operation and returns the result.
    /// </summary>
    /// <param name="password">The password value.</param>
    /// <returns>The operation result.</returns>
    byte[] HashPassword(ReadOnlySpan<char> password);
    /// <summary>
    /// Performs the verify password operation and returns the result.
    /// </summary>
    /// <param name="password">The password value.</param>
    /// <param name="encodedHash">The encoded hash value.</param>
    /// <returns>The operation result.</returns>
    bool VerifyPassword(ReadOnlySpan<char> password, ReadOnlySpan<byte> encodedHash);
}


