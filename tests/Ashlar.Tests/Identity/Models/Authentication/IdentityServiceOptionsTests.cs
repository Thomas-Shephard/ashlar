namespace Ashlar.Tests.Identity.Models.Authentication;

internal sealed class IdentityServiceOptionsTests
{
    [TestCase(0, true)]
    [TestCase(-1, false)]
    public void ValidateChecksLastUsedAtUpdateThreshold(long ticks, bool expected)
    {
        Assert.That(IdentityServiceOptions.Validate(new IdentityServiceOptions
        {
            LastUsedAtUpdateThreshold = TimeSpan.FromTicks(ticks)
        }), Is.EqualTo(expected));
    }

    [Test]
    public void ValidateRejectsNull() => Assert.That(IdentityServiceOptions.Validate(null), Is.False);
}
