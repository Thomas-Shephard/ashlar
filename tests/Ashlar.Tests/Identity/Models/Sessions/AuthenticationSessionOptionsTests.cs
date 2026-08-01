namespace Ashlar.Tests.Identity.Models.Sessions;

internal sealed class AuthenticationSessionOptionsTests
{
    [Test]
    public void ValidateAcceptsDefaults() => Assert.That(AuthenticationSessionOptions.Validate(new()), Is.True);

    [TestCaseSource(nameof(InvalidOptions))]
    public void ValidateRejectsInvalidOptions(AuthenticationSessionOptions? options)
    {
        Assert.That(AuthenticationSessionOptions.Validate(options), Is.False);
    }

    private static IEnumerable<AuthenticationSessionOptions?> InvalidOptions()
    {
        yield return null;
        yield return new() { DefaultLifetime = TimeSpan.Zero };
        yield return new() { MaximumLifetime = TimeSpan.FromDays(1), DefaultLifetime = TimeSpan.FromDays(2) };
        yield return new() { LastSeenUpdateThreshold = TimeSpan.FromTicks(-1) };
        yield return new() { TokenByteLength = 31 };
        yield return new() { TokenByteLength = 193 };
        yield return new() { MaxIpAddressLength = 0 };
        yield return new() { MaxUserAgentLength = 0 };
        yield return new() { MaxMetadataLength = 0 };
    }
}
