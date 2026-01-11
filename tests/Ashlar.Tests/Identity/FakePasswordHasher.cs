using Ashlar.Security.Hashing;

namespace Ashlar.Tests.Identity;

public sealed class FakePasswordHasher : IPasswordHasher
{
    public byte Version { get; init; } = 0x01;
    public bool ShouldVerify { get; set; } = true;

    public byte[] HashPassword(ReadOnlySpan<char> password)
    {
        return [Version, 0, 0, 0];
    }

    public bool VerifyPassword(ReadOnlySpan<char> password, ReadOnlySpan<byte> encodedHash)
    {
        return ShouldVerify;
    }
}
