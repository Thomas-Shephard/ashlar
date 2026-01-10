using System.Security.Cryptography;

namespace Ashlar.Security.Hashing;

public sealed class PasswordHasherV1 : IPasswordHasher
{
    public byte Version => 0x01;
    private const int SaltLength = 16;
    private const int HashLength = 32;
    private const int TotalLength = IPasswordHasher.VersionLength + SaltLength + HashLength;
    private const int IterationCount = 600_000;
    private static readonly HashAlgorithmName HashAlgorithm = HashAlgorithmName.SHA256;

    private readonly ReadOnlyMemory<byte> _dummySalt = RandomNumberGenerator.GetBytes(SaltLength);
    private readonly ReadOnlyMemory<byte> _dummyHash = RandomNumberGenerator.GetBytes(HashLength);

    public byte[] HashPassword(ReadOnlySpan<char> password)
    {
        byte[] encodedHash = new byte[TotalLength];
        encodedHash[0] = Version;

        Span<byte> salt = encodedHash.AsSpan(IPasswordHasher.VersionLength, SaltLength);
        RandomNumberGenerator.Fill(salt);

        Rfc2898DeriveBytes.Pbkdf2(password, salt, encodedHash.AsSpan(IPasswordHasher.VersionLength + SaltLength, HashLength), IterationCount, HashAlgorithm);

        return encodedHash;
    }

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
