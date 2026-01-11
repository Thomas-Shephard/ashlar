using Ashlar.Identity.Models;

namespace Ashlar.Tests.Identity;

public class ModelTests
{
    [Test]
    public void TenantPropertiesShouldWork()
    {
        var id = Guid.NewGuid();
        var tenant = new Tenant
        {
            Id = id,
            Name = "Acme",
            Identifier = "acme-corp",
            IsActive = false
        };

        using (Assert.EnterMultipleScope())
        {
            Assert.That(tenant.Id, Is.EqualTo(id));
            Assert.That(tenant.Name, Is.EqualTo("Acme"));
            Assert.That(tenant.Identifier, Is.EqualTo("acme-corp"));
            Assert.That(tenant.IsActive, Is.False);
        }

        tenant.Name = "New Acme";
        tenant.IsActive = true;
        
        using (Assert.EnterMultipleScope())
        {
            Assert.That(tenant.Name, Is.EqualTo("New Acme"));
            Assert.That(tenant.IsActive, Is.True);
        }
    }

    [Test]
    public void UserCredentialPropertiesShouldWork()
    {
        var id = Guid.NewGuid();
        var userId = Guid.NewGuid();
        var credential = new UserCredential
        {
            Id = id,
            UserId = userId,
            ProviderType = ProviderType.Local,
            ProviderName = "Local",
            ProviderKey = "key",
            CredentialValue = "val"
        };

        using (Assert.EnterMultipleScope())
        {
            Assert.That(credential.Id, Is.EqualTo(id));
            Assert.That(credential.UserId, Is.EqualTo(userId));
            Assert.That(credential.ProviderType, Is.EqualTo(ProviderType.Local));
            Assert.That(credential.ProviderName, Is.EqualTo("Local"));
            Assert.That(credential.ProviderKey, Is.EqualTo("key"));
            Assert.That(credential.CredentialValue, Is.EqualTo("val"));
        }
    }
}
