using Ashlar.Auditing;

namespace Ashlar.Tests.Identity.Models;

internal sealed class AdministrationRequestModelTests
{
    [Test]
    public void SearchRequestValidationRejectsNullRequests()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => SearchUsersRequest.ThrowIfInvalid(null));
            Assert.Throws<ArgumentNullException>(() => SearchCredentialsRequest.ThrowIfInvalid(null));
            Assert.Throws<ArgumentNullException>(() => SearchAuthenticationSessionsRequest.ThrowIfInvalid(null));
            Assert.Throws<ArgumentNullException>(() => SearchSecurityEventsRequest.ThrowIfInvalid(null));
        }
    }

    [Test]
    public void DetailRequestValidationRejectsNullRequests()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => UserAdministrationDetailRequest.ThrowIfInvalid(null));
            Assert.Throws<ArgumentNullException>(() => CredentialAdministrationDetailRequest.ThrowIfInvalid(null));
            Assert.Throws<ArgumentNullException>(() => AuthenticationSessionAdministrationDetailRequest.ThrowIfInvalid(null));
            Assert.Throws<ArgumentNullException>(() => SecurityEventAdministrationDetailRequest.ThrowIfInvalid(null));
        }
    }

    [Test]
    public void DetailRequestValidationRejectsEmptyIds()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentException>(() => UserAdministrationDetailRequest.ThrowIfInvalid(new UserAdministrationDetailRequest(Guid.Empty, TenantContext.Global)));
            Assert.Throws<ArgumentException>(() => CredentialAdministrationDetailRequest.ThrowIfInvalid(new CredentialAdministrationDetailRequest(Guid.Empty, TenantContext.Global)));
            Assert.Throws<ArgumentException>(() => AuthenticationSessionAdministrationDetailRequest.ThrowIfInvalid(new AuthenticationSessionAdministrationDetailRequest(Guid.Empty, TenantContext.Global)));
            Assert.Throws<ArgumentException>(() => SecurityEventAdministrationDetailRequest.ThrowIfInvalid(new SecurityEventAdministrationDetailRequest(Guid.Empty, TenantContext.Global)));
        }
    }
}
