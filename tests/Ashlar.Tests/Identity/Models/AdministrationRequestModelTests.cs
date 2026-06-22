using Ashlar.Auditing;
using Ashlar.Identity.Models.AccountLockout;

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
    public void SearchRequestValidationRejectsInvalidProviders()
    {
        var unknownProvider = new AuthenticationProviderKey((ProviderType)ProviderType.StorageFallbackValue, "unknown");

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentException>(() => SearchAccountLockoutsRequest.ThrowIfInvalid(new SearchAccountLockoutsRequest { Tenant = TenantContext.Global, Provider = new AuthenticationProviderKey() }));
            Assert.Throws<ArgumentException>(() => SearchAccountLockoutsRequest.ThrowIfInvalid(new SearchAccountLockoutsRequest { Tenant = TenantContext.Global, Provider = unknownProvider }));
        }
    }

    [Test]
    public void DetailRequestValidationRejectsNullRequests()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => UserAdministrationDetailRequest.ThrowIfInvalid(null));
            Assert.Throws<ArgumentNullException>(() => CredentialAdministrationLookupRequest.ThrowIfInvalid(null));
            Assert.Throws<ArgumentNullException>(() => AuthenticationSessionAdministrationLookupRequest.ThrowIfInvalid(null));
            Assert.Throws<ArgumentNullException>(() => SecurityEventAdministrationDetailRequest.ThrowIfInvalid(null));
        }
    }

    [Test]
    public void DetailRequestValidationRejectsEmptyIds()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentException>(() => UserAdministrationDetailRequest.ThrowIfInvalid(new UserAdministrationDetailRequest(Guid.Empty, TenantContext.Global)));
            Assert.Throws<ArgumentException>(() => CredentialAdministrationLookupRequest.ThrowIfInvalid(new CredentialAdministrationLookupRequest(Guid.Empty, TenantContext.Global)));
            Assert.Throws<ArgumentException>(() => AuthenticationSessionAdministrationLookupRequest.ThrowIfInvalid(new AuthenticationSessionAdministrationLookupRequest(Guid.Empty, TenantContext.Global)));
            Assert.Throws<ArgumentException>(() => SecurityEventAdministrationDetailRequest.ThrowIfInvalid(new SecurityEventAdministrationDetailRequest(Guid.Empty, TenantContext.Global)));
        }
    }
}
