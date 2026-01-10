using Ashlar.Security.Hashing;

namespace Ashlar.Tests.Security;

public class PasswordHasherV1Tests
{
    private const int ExpectedHashLength = 1 + 16 + 32;
    private PasswordHasherV1 _hasher;

    [SetUp]
    public void Setup()
    {
        _hasher = new PasswordHasherV1();
    }

    [Test]
    public void HashPasswordShouldProduceCorrectLength()
    {
        var password = "password123".AsSpan();
        var hash = _hasher.HashPassword(password);

        Assert.That(hash, Has.Length.EqualTo(ExpectedHashLength));
        using (Assert.EnterMultipleScope())
        {
            Assert.That(hash[0], Is.EqualTo(_hasher.Version));
            Assert.That(_hasher.Version, Is.EqualTo(0x01));
        }
    }

    [Test]
    public void HashPasswordWithEmptyPasswordShouldSucceed()
    {
        var password = "".AsSpan();
        var hash = _hasher.HashPassword(password);

        Assert.That(hash, Has.Length.EqualTo(ExpectedHashLength));
        Assert.That(hash[0], Is.EqualTo(_hasher.Version));
    }

    [Test]
    public void HashPasswordShouldProduceUniqueHashesForSamePassword()
    {
        var password = "password123".AsSpan();
        var hash1 = _hasher.HashPassword(password);
        var hash2 = _hasher.HashPassword(password);

        Assert.That(hash1, Is.Not.EqualTo(hash2));
    }

    [Test]
    public void VerifyPasswordWithCorrectPasswordShouldReturnTrue()
    {
        var password = "SecurePassword123!".AsSpan();
        var hash = _hasher.HashPassword(password);

        var result = _hasher.VerifyPassword(password, hash);

        Assert.That(result, Is.True);
    }

    [Test]
    public void VerifyPasswordWithWrongPasswordShouldReturnFalse()
    {
        var password = "SecurePassword123!".AsSpan();
        var wrongPassword = "WrongPassword123!".AsSpan();
        var hash = _hasher.HashPassword(password);

        var result = _hasher.VerifyPassword(wrongPassword, hash);

        Assert.That(result, Is.False);
    }

    [Test]
    public void VerifyPasswordWithMalformedHashShouldReturnFalse()
    {
        var password = "password123".AsSpan();
        var malformedHash = new byte[10];

        var result = _hasher.VerifyPassword(password, malformedHash);

        Assert.That(result, Is.False);
    }

    [Test]
    public void VerifyPasswordWithEmptyPasswordAndWrongHashShouldReturnFalse()
    {
        var password = "password123".AsSpan();
        var emptyPassword = "".AsSpan();
        var hash = _hasher.HashPassword(password);

        var result = _hasher.VerifyPassword(emptyPassword, hash);

        Assert.That(result, Is.False);
    }

    [Test]
    public void VerifyPasswordWithEmptyHashShouldReturnFalse()
    {
        var password = "password123".AsSpan();

        var result = _hasher.VerifyPassword(password, []);

        Assert.That(result, Is.False);
    }

    [Test]
    public void VerifyPasswordWithEmptyPasswordShouldReturnTrueIfCorrect()
    {
        var password = "".AsSpan();
        var hash = _hasher.HashPassword(password);

        var result = _hasher.VerifyPassword(password, hash);

        Assert.That(result, Is.True);
    }
}
