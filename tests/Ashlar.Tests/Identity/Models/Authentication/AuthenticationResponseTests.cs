namespace Ashlar.Tests.Identity.Models.Authentication;

internal sealed class AuthenticationResponseTests
{
    [Test]
    public void ConstructorShouldDefaultCredentialUpdatePersistedToFalse()
    {
        var response = new AuthenticationResponse(true, Status: AuthenticationStatus.SuccessWithCredentialUpdate);

        Assert.That(response.CredentialUpdatePersisted, Is.False);
    }

    [Test]
    public void ConstructorShouldPreserveCredentialUpdatePersisted()
    {
        var response = new AuthenticationResponse(true, Status: AuthenticationStatus.SuccessWithCredentialUpdate, CredentialUpdatePersisted: true);

        Assert.That(response.CredentialUpdatePersisted, Is.True);
    }

    [Test]
    public void SingleValueClaimsConstructorShouldDefaultCredentialUpdatePersistedToFalse()
    {
        var response = new AuthenticationResponse(true, null, AuthenticationStatus.SuccessWithCredentialUpdate, new Dictionary<string, string> { ["sub"] = "123" });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Claims?["sub"], Is.EqualTo(["123"]));
            Assert.That(response.CredentialUpdatePersisted, Is.False);
        }
    }
}
