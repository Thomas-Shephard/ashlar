namespace Ashlar.Tests.Identity.Models.Mfa;

[TestFixture]
internal sealed class AuthenticationFactorTypesTests
{
    [TestCase("totp", "TOTP", true)]
    [TestCase("custom_step_up", "custom-step-up", true)]
    [TestCase("-", "_", false)]
    [TestCase(null, "totp", false)]
    [TestCase(" ", "", true)]
    public void MatchesComparesFactorTypesSafely(string? left, string? right, bool expected)
    {
        Assert.That(AuthenticationFactorTypes.Matches(left, right), Is.EqualTo(expected));
    }
}
