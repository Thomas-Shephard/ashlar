using Ashlar.Security.Hashing;

namespace Ashlar.Tests.Security;

public class PasswordHasherSelectorTests
{
    private PasswordHasherV1 _v1Hasher;
    private PasswordHasherSelector _selector;

    [SetUp]
    public void Setup()
    {
        _v1Hasher = new PasswordHasherV1();
        _selector = new PasswordHasherSelector([_v1Hasher]);
    }

    [Test]
    public void ConstructorShouldThrowIfHashersIsNull()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new PasswordHasherSelector(null!));
    }

    [Test]
    public void ConstructorShouldThrowIfHashersIsEmpty()
    {
        var ex = Assert.Throws<ArgumentException>(() => _ = new PasswordHasherSelector([]));
        Assert.That(ex.ParamName, Is.EqualTo("hashers"));
    }

    [Test]
    public void ConstructorShouldThrowIfHashersContainsNull()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new PasswordHasherSelector([null!]));
    }

    [Test]
    public void ConstructorShouldThrowIfDuplicateVersionsExist()
    {
        var hasher1 = new PasswordHasherV1();
        var hasher2 = new PasswordHasherV1();

        var ex = Assert.Throws<ArgumentException>(() => _ = new PasswordHasherSelector([hasher1, hasher2]));
        Assert.That(ex.Message, Does.Contain("Duplicate password hasher version: 1"));
    }

    [Test]
    public void DefaultHasherShouldReturnHighestVersion()
    {
        var v1 = new PasswordHasherV1();
        var v2 = new MockHasher(0x02);
        var selector = new PasswordHasherSelector([v1, v2]);

        Assert.That(selector.DefaultHasher, Is.SameAs(v2));
    }

    [Test]
    public void GetHasherShouldReturnCorrectHasher()
    {
        var hash = _v1Hasher.HashPassword("pass".AsSpan());
        var hasher = _selector.GetHasher(hash);

        Assert.That(hasher, Is.Not.Null);
        Assert.That(hasher.Version, Is.EqualTo(0x01));
    }

    [Test]
    public void GetHasherShouldReturnDefaultForUnknownVersion()
    {
        var hash = new byte[] { 0x99, 0x00 };
        var hasher = _selector.GetHasher(hash);

        Assert.That(hasher, Is.Not.Null);
        Assert.That(hasher.Version, Is.EqualTo(0x01));
    }

    [Test]
    public void GetHasherShouldReturnDefaultForEmpty()
    {
        var hasher = _selector.GetHasher([]);
        Assert.That(hasher, Is.Not.Null);
        Assert.That(hasher.Version, Is.EqualTo(0x01));
    }

    [Test]
    public void VerifyPasswordShouldReturnSuccessForCurrentVersion()
    {
        var password = "password123".AsSpan();
        var hash = _v1Hasher.HashPassword(password);

        var result = _selector.VerifyPassword(password, hash);

        Assert.That(result, Is.EqualTo(PasswordVerificationResult.Success));
    }

    [Test]
    public void VerifyPasswordShouldReturnFailedForWrongPassword()
    {
        var password = "password123".AsSpan();
        var hash = _v1Hasher.HashPassword(password);

        var result = _selector.VerifyPassword("wrong".AsSpan(), hash);

        Assert.That(result, Is.EqualTo(PasswordVerificationResult.Failed));
    }

    [Test]
    public void VerifyPasswordShouldReturnSuccessRehashNeededForOldVersion()
    {
        var v1 = new PasswordHasherV1();
        var v2 = new MockHasher(0x02);
        var selector = new PasswordHasherSelector([v1, v2]);

        var password = "password123".AsSpan();
        var hash = v1.HashPassword(password);

        var result = selector.VerifyPassword(password, hash);

        Assert.That(result, Is.EqualTo(PasswordVerificationResult.SuccessRehashNeeded));
    }

    private sealed class MockHasher(byte version) : IPasswordHasher
    {
        public byte Version => version;
        public byte[] HashPassword(ReadOnlySpan<char> password) => [];
        public bool VerifyPassword(ReadOnlySpan<char> password, ReadOnlySpan<byte> saltAndHash) => false;
    }
}
