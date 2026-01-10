namespace Ashlar.Security.Hashing;

public interface IPasswordHasher
{
    public const int VersionLength = 1;
    byte Version { get; }
    byte[] HashPassword(ReadOnlySpan<char> password);
    bool VerifyPassword(ReadOnlySpan<char> password, ReadOnlySpan<byte> encodedHash);
}
