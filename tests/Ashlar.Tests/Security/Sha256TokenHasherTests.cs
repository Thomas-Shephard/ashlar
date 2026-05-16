using Ashlar.Security.Tokens;

namespace Ashlar.Tests.Security;

internal sealed class Sha256TokenHasherTests
{
    [Test]
    public void HashTokenShouldReturnStableHash()
    {
        var hasher = new Sha256TokenHasher();
        const string token = "security-token-value";

        var first = hasher.HashToken(token);
        var second = hasher.HashToken(token);

        Assert.That(second, Is.EqualTo(first));
    }

    [Test]
    public void HashTokenShouldNotReturnRawToken()
    {
        var hasher = new Sha256TokenHasher();
        const string token = "security-token-value";

        var hash = hasher.HashToken(token);

        Assert.That(hash, Is.Not.EqualTo(token));
    }

    [Test]
    public void HashTokenShouldProduceDifferentHashesForDifferentTokens()
    {
        var hasher = new Sha256TokenHasher();

        var first = hasher.HashToken("security-token-one");
        var second = hasher.HashToken("security-token-two");

        Assert.That(second, Is.Not.EqualTo(first));
    }

    [Test]
    public void HashTokenShouldSupportAstralUnicodeCharacters()
    {
        var hasher = new Sha256TokenHasher();
        const string token = "security-token-\U0001F510";

        var hash = hasher.HashToken(token);

        Assert.That(hash, Does.StartWith("sha256:"));
    }

    [Test]
    public void HashTokenShouldRejectBlankToken()
    {
        var hasher = new Sha256TokenHasher();

        Assert.Throws<ArgumentException>(() => hasher.HashToken(" "));
    }

    [Test]
    public void HashTokenShouldRejectTokensLongerThanMaximum()
    {
        var hasher = new Sha256TokenHasher();
        var token = new string('a', 257);

        Assert.Throws<ArgumentException>(() => hasher.HashToken(token));
    }
}
