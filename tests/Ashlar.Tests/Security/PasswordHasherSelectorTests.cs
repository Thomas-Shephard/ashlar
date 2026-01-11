using Ashlar.Security.Hashing;
using Ashlar.Tests.Identity;

namespace Ashlar.Tests.Security;

public class PasswordHasherSelectorTests
{
    [Test]
    public void ConstructorShouldThrowOnNullHashers()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new PasswordHasherSelector(null!));
    }

    [Test]
    public void ConstructorShouldThrowOnEmptyHashers()
    {
        Assert.Throws<ArgumentException>(() => _ = new PasswordHasherSelector([]));
    }

    [Test]
    public void ConstructorShouldThrowOnDuplicateVersion()
    {
        var hasher1 = new FakePasswordHasher { Version = 1 };
        var hasher2 = new FakePasswordHasher { Version = 1 };

        Assert.Throws<ArgumentException>(() => _ = new PasswordHasherSelector([hasher1, hasher2]));
    }

    [Test]
    public void ConstructorShouldThrowOnNullHasherInList()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new PasswordHasherSelector([null!]));
    }

    [Test]
    public void DefaultHasherShouldBeHighestVersion()
    {
        var hasher1 = new FakePasswordHasher { Version = 1 };
        var hasher2 = new FakePasswordHasher { Version = 2 };

        var selector = new PasswordHasherSelector([hasher1, hasher2]);
        Assert.That(selector.DefaultHasher.Version, Is.EqualTo(2));
    }

    [Test]
    public void DefaultHasherShouldBeHighestVersionEvenIfAddedInDecreasingOrder()
    {
        var hasher1 = new FakePasswordHasher { Version = 1 };
        var hasher2 = new FakePasswordHasher { Version = 2 };

        var selector = new PasswordHasherSelector([hasher2, hasher1]);
        Assert.That(selector.DefaultHasher.Version, Is.EqualTo(2));
    }

    [Test]
    public void GetHasherWithExactVersionLengthShouldWork()
    {
        var hasher = new FakePasswordHasher { Version = 0x01 };
        var selector = new PasswordHasherSelector([hasher]);

        var result = selector.GetHasher([0x01]);
        Assert.That(result, Is.EqualTo(hasher));
    }

    [Test]
    public void VerifyPasswordShouldReturnFailedWhenHasherFails()
    {
        var hasher = new FakePasswordHasher { Version = 1, ShouldVerify = false };
        var selector = new PasswordHasherSelector([hasher]);

        var result = selector.VerifyPassword("pass", [0x01]);
        Assert.That(result, Is.EqualTo(PasswordVerificationResult.Failed));
    }

    [Test]
    public void GetHasherShouldReturnDefaultOnEmptyHash()
    {
        var hasher = new FakePasswordHasher { Version = 1 };
        var selector = new PasswordHasherSelector([hasher]);

        var result = selector.GetHasher(ReadOnlySpan<byte>.Empty);
        Assert.That(result, Is.EqualTo(hasher));
    }

    [Test]
    public void GetHasherShouldReturnDefaultOnUnknownVersion()
    {
        var hasher = new FakePasswordHasher { Version = 1 };
        var selector = new PasswordHasherSelector([hasher]);

        var result = selector.GetHasher([0x99]);
        Assert.That(result, Is.EqualTo(hasher));
    }

    [Test]
    public void VerifyPasswordShouldReturnSuccessRehashNeededOnOldVersion()
    {
        var oldHasher = new FakePasswordHasher { Version = 1, ShouldVerify = true };
        var newHasher = new FakePasswordHasher { Version = 2 };

        var selector = new PasswordHasherSelector([oldHasher, newHasher]);

        var result = selector.VerifyPassword("pass", [0x01]);
        Assert.That(result, Is.EqualTo(PasswordVerificationResult.SuccessRehashNeeded));
    }
}
