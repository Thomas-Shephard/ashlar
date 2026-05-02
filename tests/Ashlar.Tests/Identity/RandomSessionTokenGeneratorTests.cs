using Ashlar.Identity;

namespace Ashlar.Tests.Identity;

public sealed class RandomSessionTokenGeneratorTests
{
    [Test]
    public void GenerateTokenShouldReturnUrlSafeHighEntropyToken()
    {
        var generator = new RandomSessionTokenGenerator();

        var token = generator.GenerateToken(32);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(token, Has.Length.EqualTo(43));
            Assert.That(token, Does.Not.Contain("+"));
            Assert.That(token, Does.Not.Contain("/"));
            Assert.That(token, Does.Not.Contain("="));
        }
    }

    [Test]
    public void GenerateTokenShouldReturnDifferentTokens()
    {
        var generator = new RandomSessionTokenGenerator();

        var first = generator.GenerateToken(32);
        var second = generator.GenerateToken(32);

        Assert.That(second, Is.Not.EqualTo(first));
    }

    [Test]
    public void GenerateTokenShouldRejectLessThanThirtyTwoBytes()
    {
        var generator = new RandomSessionTokenGenerator();

        Assert.Throws<ArgumentOutOfRangeException>(() => generator.GenerateToken(31));
    }
}
