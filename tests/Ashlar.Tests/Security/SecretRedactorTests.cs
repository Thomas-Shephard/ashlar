using Ashlar.Security;

namespace Ashlar.Tests.Security;

[TestFixture]
public class SecretRedactorTests
{
    [Test]
    public void ContainsSecretShouldReturnTrueWhenSecretIsPresent()
    {
        var ex = new InvalidOperationException("Error with secret_password");
        Assert.That(SecretRedactor.ContainsSecret(ex, "secret_password"), Is.True);
    }

    [Test]
    public void ContainsSecretShouldReturnTrueEvenForShortSecrets()
    {
        var ex = new InvalidOperationException("Error with abc");
        Assert.That(SecretRedactor.ContainsSecret(ex, "abc"), Is.True);
    }

    [Test]
    public void ContainsSecretShouldReturnFalseWhenSecretIsMissing()
    {
        var ex = new InvalidOperationException("Error message");
        Assert.That(SecretRedactor.ContainsSecret(ex, "password"), Is.False);
    }

    [Test]
    public void ContainsSecretShouldReturnFalseWhenExceptionOrSecretIsMissing()
    {
        var ex = new InvalidOperationException("Error message");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(SecretRedactor.ContainsSecret(null, "password"), Is.False);
            Assert.That(SecretRedactor.ContainsSecret(ex, null), Is.False);
            Assert.That(SecretRedactor.ContainsSecret(ex, string.Empty), Is.False);
        }
    }

    [Test]
    public void RedactExceptionShouldReplaceSecrets()
    {
        var ex = new InvalidOperationException("Error with secret_password and another_secret");
        var result = SecretRedactor.Redact(ex, "secret_password", "another_secret");

        Assert.That(result, Does.Not.Contain("secret_password"));
        Assert.That(result, Does.Not.Contain("another_secret"));
        Assert.That(result, Does.Contain(SecretRedactor.RedactedPlaceholder));
    }

    [Test]
    public void RedactExceptionShouldReplaceShortSecrets()
    {
        var ex = new InvalidOperationException("Error with abc");
        var result = SecretRedactor.Redact(ex, "abc");

        Assert.That(result, Does.Not.Contain("abc"));
        Assert.That(result, Does.Contain(SecretRedactor.RedactedPlaceholder));
    }

    [Test]
    public void RedactStringShouldReplaceMultipleSecrets()
    {
        const string input = "The secret is 'S3CR3T' and the token is 'T0K3N'.";
        var result = SecretRedactor.Redact(input, "S3CR3T", "T0K3N");

        Assert.That(result, Is.EqualTo($"The secret is '{SecretRedactor.RedactedPlaceholder}' and the token is '{SecretRedactor.RedactedPlaceholder}'."));
    }

    [Test]
    public void RedactStringShouldHandleNullOrEmpty()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(SecretRedactor.Redact((string?)null, "secret"), Is.EqualTo(string.Empty));
            Assert.That(SecretRedactor.Redact(string.Empty, "secret"), Is.EqualTo(string.Empty));
            Assert.That(SecretRedactor.Redact("some string"), Is.EqualTo("some string"));
            Assert.That(SecretRedactor.Redact("some string", null, string.Empty), Is.EqualTo("some string"));
        }
    }
}
