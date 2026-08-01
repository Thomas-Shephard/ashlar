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
    public void LookupRequestValidationRejectsNullRequests()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => UserAdministrationLookupRequest.ThrowIfInvalid(null));
            Assert.Throws<ArgumentNullException>(() => CredentialAdministrationLookupRequest.ThrowIfInvalid(null));
            Assert.Throws<ArgumentNullException>(() => AuthenticationSessionAdministrationLookupRequest.ThrowIfInvalid(null));
            Assert.Throws<ArgumentNullException>(() => SecurityEventAdministrationLookupRequest.ThrowIfInvalid(null));
        }
    }

    [Test]
    public void LookupRequestValidationRejectsEmptyIds()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentException>(() => UserAdministrationLookupRequest.ThrowIfInvalid(new UserAdministrationLookupRequest(Guid.Empty, TenantContext.Global)));
            Assert.Throws<ArgumentException>(() => CredentialAdministrationLookupRequest.ThrowIfInvalid(new CredentialAdministrationLookupRequest(Guid.Empty, TenantContext.Global)));
            Assert.Throws<ArgumentException>(() => AuthenticationSessionAdministrationLookupRequest.ThrowIfInvalid(new AuthenticationSessionAdministrationLookupRequest(Guid.Empty, TenantContext.Global)));
            Assert.Throws<ArgumentException>(() => SecurityEventAdministrationLookupRequest.ThrowIfInvalid(new SecurityEventAdministrationLookupRequest(Guid.Empty, TenantContext.Global)));
        }
    }
}
