using Ashlar.Security.Hashing;

namespace Ashlar.Tests.Security;

public sealed class Sha256SessionTokenHasherTests
{
    [Test]
    public void HashTokenShouldReturnStableHash()
    {
        var hasher = new Sha256SessionTokenHasher();
        const string token = "session-token-value";

        var first = hasher.HashToken(token);
        var second = hasher.HashToken(token);

        Assert.That(second, Is.EqualTo(first));
    }

    [Test]
    public void HashTokenShouldNotReturnRawToken()
    {
        var hasher = new Sha256SessionTokenHasher();
        const string token = "session-token-value";

        var hash = hasher.HashToken(token);

        Assert.That(hash, Is.Not.EqualTo(token));
    }

    [Test]
    public void HashTokenShouldProduceDifferentHashesForDifferentTokens()
    {
        var hasher = new Sha256SessionTokenHasher();

        var first = hasher.HashToken("session-token-one");
        var second = hasher.HashToken("session-token-two");

        Assert.That(second, Is.Not.EqualTo(first));
    }

    [Test]
    public void HashTokenShouldSupportAstralUnicodeCharacters()
    {
        var hasher = new Sha256SessionTokenHasher();
        const string token = "session-token-\U0001F510";

        var hash = hasher.HashToken(token);

        Assert.That(hash, Does.StartWith("sha256:"));
    }

    [Test]
    public void HashTokenShouldRejectBlankToken()
    {
        var hasher = new Sha256SessionTokenHasher();

        Assert.Throws<ArgumentException>(() => hasher.HashToken(" "));
    }

    [Test]
    public void HashTokenShouldRejectTokensLongerThanMaximum()
    {
        var hasher = new Sha256SessionTokenHasher();
        var token = new string('a', 257);

        Assert.Throws<ArgumentException>(() => hasher.HashToken(token));
    }
}
