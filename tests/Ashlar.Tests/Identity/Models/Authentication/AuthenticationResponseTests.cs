namespace Ashlar.Tests.Identity.Models.Authentication;

internal sealed class AuthenticationResponseTests
{
    [TestCase(AuthenticationStatus.Success, true)]
    [TestCase(AuthenticationStatus.SuccessWithCredentialUpdate, true)]
    [TestCase(AuthenticationStatus.Failed, false)]
    [TestCase(AuthenticationStatus.Disabled, false)]
    [TestCase(AuthenticationStatus.MfaRequired, false)]
    [TestCase(AuthenticationStatus.RateLimited, false)]
    public void SucceededIsDerivedFromStatus(AuthenticationStatus status, bool succeeded)
    {
        var user = status is AuthenticationStatus.Success or AuthenticationStatus.SuccessWithCredentialUpdate or AuthenticationStatus.MfaRequired
            ? new User { Id = Guid.NewGuid(), DisplayEmail = "user@example.com" }
            : null;

        Assert.That(new AuthenticationResponse(user, status).Succeeded, Is.EqualTo(succeeded));
    }

    [TestCase(AuthenticationStatus.Success)]
    [TestCase(AuthenticationStatus.SuccessWithCredentialUpdate)]
    [TestCase(AuthenticationStatus.MfaRequired)]
    public void ConstructorRejectsMissingRequiredUser(AuthenticationStatus status)
    {
        Assert.That(() => new AuthenticationResponse(Status: status), Throws.TypeOf<ArgumentNullException>());
    }

    [Test]
    public void GetUserReturnsUserAndRejectsMissingUser()
    {
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "user@example.com" };

        using (Assert.EnterMultipleScope())
        {
            Assert.That(new AuthenticationResponse(user, AuthenticationStatus.Success).GetUser(), Is.SameAs(user));
            Assert.That(() => new AuthenticationResponse().GetUser(), Throws.InvalidOperationException);
        }
    }

    [Test]
    public void ConstructorRejectsUndefinedStatus()
    {
        Assert.That(
            () => new AuthenticationResponse(Status: (AuthenticationStatus)int.MaxValue),
            Throws.TypeOf<ArgumentOutOfRangeException>());
    }

    [TestCase(AuthenticationStatus.Failed)]
    [TestCase(AuthenticationStatus.Success)]
    [TestCase(AuthenticationStatus.Disabled)]
    [TestCase(AuthenticationStatus.MfaRequired)]
    [TestCase(AuthenticationStatus.RateLimited)]
    public void ConstructorRejectsPersistedCredentialUpdateWithoutUpdateStatus(AuthenticationStatus status)
    {
        Assert.That(
            () => new AuthenticationResponse(Status: status, CredentialUpdatePersisted: true),
            Throws.ArgumentException);
    }

    [Test]
    public void ConstructorShouldDefaultCredentialUpdatePersistedToFalse()
    {
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "user@example.com" };
        var response = new AuthenticationResponse(user, AuthenticationStatus.SuccessWithCredentialUpdate);

        Assert.That(response.CredentialUpdatePersisted, Is.False);
    }

    [Test]
    public void ConstructorShouldPreserveCredentialUpdatePersisted()
    {
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "user@example.com" };
        var response = new AuthenticationResponse(user, AuthenticationStatus.SuccessWithCredentialUpdate, CredentialUpdatePersisted: true);

        Assert.That(response.CredentialUpdatePersisted, Is.True);
    }
}
