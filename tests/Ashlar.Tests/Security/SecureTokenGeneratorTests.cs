using System.Text.RegularExpressions;
using Ashlar.Security.Tokens;

namespace Ashlar.Tests.Security;

internal sealed partial class SecureTokenGeneratorTests
{
    private static readonly Regex UrlSafeTokenPattern = UrlSafeTokenPatternRegex();

    [Test]
    public void GenerateTokenShouldReturnNonEmptyUrlSafeToken()
    {
        var generator = new SecureTokenGenerator();

        var token = generator.GenerateToken();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(token, Is.Not.Empty);
            Assert.That(UrlSafeTokenPattern.IsMatch(token), Is.True);
            Assert.That(token, Does.Not.Contain("="));
        }
    }

    [Test]
    public void GenerateTokenShouldReturnUniqueTokensAcrossManyGenerations()
    {
        var generator = new SecureTokenGenerator();
        var tokens = Enumerable.Range(0, 100)
            .Select(_ => generator.GenerateToken())
            .ToArray();

        Assert.That(tokens.Distinct(StringComparer.Ordinal).Count(), Is.EqualTo(tokens.Length));
    }

    [Test]
    public void GenerateTokenShouldHonorConfiguredByteLength()
    {
        var generator = new SecureTokenGenerator();

        var token = generator.GenerateToken(48);

        Assert.That(token, Has.Length.EqualTo(64));
    }

    [Test]
    public void GenerateTokenShouldRejectLessThanMinimumByteLength()
    {
        var generator = new SecureTokenGenerator();

        Assert.Throws<ArgumentOutOfRangeException>(() => generator.GenerateToken(ISecureTokenGenerator.MinimumByteLength - 1));
    }

    [Test]
    public void GenerateTokenShouldRejectGreaterThanMaximumByteLength()
    {
        var generator = new SecureTokenGenerator();

        Assert.Throws<ArgumentOutOfRangeException>(() => generator.GenerateToken(ISecureTokenGenerator.MaximumByteLength + 1));
    }

    [GeneratedRegex("^[A-Za-z0-9_-]+$", RegexOptions.Compiled)]
    private static partial Regex UrlSafeTokenPatternRegex();
}


