using System.Security.Cryptography;

namespace Ashlar.Security.Hashing;

/// <summary>
/// Provides password hasher v1 behavior.
/// </summary>
public sealed class PasswordHasherV1 : IPasswordHasher
{
    /// <summary>
    /// Gets or sets the version value.
    /// </summary>
    public byte Version => 0x01;
    private const int SaltLength = 16;
    private const int HashLength = 32;
    private const int TotalLength = IPasswordHasher.VersionLength + SaltLength + HashLength;
    private const int IterationCount = 600_000;
    private static readonly HashAlgorithmName HashAlgorithm = HashAlgorithmName.SHA256;

    private readonly ReadOnlyMemory<byte> _dummySalt = RandomNumberGenerator.GetBytes(SaltLength);
    private readonly ReadOnlyMemory<byte> _dummyHash = RandomNumberGenerator.GetBytes(HashLength);

    /// <summary>
    /// Performs the hash password operation and returns the result.
    /// </summary>
    /// <param name="password">The password value.</param>
    /// <returns>The operation result.</returns>
    public byte[] HashPassword(ReadOnlySpan<char> password)
    {
        byte[] encodedHash = new byte[TotalLength];
        encodedHash[0] = Version;

        Span<byte> salt = encodedHash.AsSpan(IPasswordHasher.VersionLength, SaltLength);
        RandomNumberGenerator.Fill(salt);

        Rfc2898DeriveBytes.Pbkdf2(password, salt, encodedHash.AsSpan(IPasswordHasher.VersionLength + SaltLength, HashLength), IterationCount, HashAlgorithm);

        return encodedHash;
    }

    /// <summary>
    /// Performs the verify password operation and returns the result.
    /// </summary>
    /// <param name="password">The password value.</param>
    /// <param name="encodedHash">The encoded hash value.</param>
    /// <returns>The operation result.</returns>
    public bool VerifyPassword(ReadOnlySpan<char> password, ReadOnlySpan<byte> encodedHash)
    {
        bool isValidFormat = encodedHash is { Length: TotalLength } && encodedHash[0] == Version;

        ReadOnlySpan<byte> salt;
        ReadOnlySpan<byte> expectedHash;

        if (isValidFormat)
        {
            salt = encodedHash.Slice(IPasswordHasher.VersionLength, SaltLength);
            expectedHash = encodedHash.Slice(IPasswordHasher.VersionLength + SaltLength, HashLength);
        }
        else
        {
            salt = _dummySalt.Span;
            expectedHash = _dummyHash.Span;
        }

        Span<byte> actualHash = stackalloc byte[HashLength];
        Rfc2898DeriveBytes.Pbkdf2(password, salt, actualHash, IterationCount, HashAlgorithm);

        bool matches = CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
        CryptographicOperations.ZeroMemory(actualHash);

        // Do not use short-circuiting to avoid timing attacks
        return matches & isValidFormat;
    }
}
