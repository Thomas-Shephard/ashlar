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
}
