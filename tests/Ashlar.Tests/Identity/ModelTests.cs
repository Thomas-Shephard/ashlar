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
        var createdAt = DateTimeOffset.UtcNow.AddDays(-1);
        var updatedAt = DateTimeOffset.UtcNow;
        var expiresAt = DateTimeOffset.UtcNow.AddDays(1);
        var revokedAt = DateTimeOffset.UtcNow.AddHours(-1);
        var credential = new UserCredential
        {
            Id = id,
            UserId = userId,
            ProviderType = ProviderType.Local,
            ProviderName = AuthenticationProviderKey.Local.Name,
            ProviderKey = "key",
            Version = "v1",
            CreatedAt = createdAt,
            Status = CredentialStatus.Active,
            UpdatedAt = updatedAt,
            ExpiresAt = expiresAt,
            RevokedAt = revokedAt,
            Purpose = "primary",
            CredentialValue = "val"
        };

        using (Assert.EnterMultipleScope())
        {
            Assert.That(credential.Id, Is.EqualTo(id));
            Assert.That(credential.UserId, Is.EqualTo(userId));
            Assert.That(credential.ProviderType, Is.EqualTo(ProviderType.Local));
            Assert.That(credential.ProviderName, Is.EqualTo(AuthenticationProviderKey.Local.Name));
            Assert.That(credential.ProviderKey, Is.EqualTo("key"));
            Assert.That(credential.Version, Is.EqualTo("v1"));
            Assert.That(credential.CreatedAt, Is.EqualTo(createdAt));
            Assert.That(credential.UpdatedAt, Is.EqualTo(updatedAt));
            Assert.That(credential.ExpiresAt, Is.EqualTo(expiresAt));
            Assert.That(credential.RevokedAt, Is.EqualTo(revokedAt));
            Assert.That(credential.Status, Is.EqualTo(CredentialStatus.Active));
            Assert.That(credential.Purpose, Is.EqualTo("primary"));
            Assert.That(credential.CredentialValue, Is.EqualTo("val"));
        }
    }

    [Test]
    public void UserCredentialIsAvailableShouldReflectLifecycleState()
    {
        var now = DateTimeOffset.UtcNow;

        using (Assert.EnterMultipleScope())
        {
            var activeWithoutExpiry = CreateCredential();
            Assert.That(activeWithoutExpiry.IsAvailable(now), Is.True);

            var expiredAtNow = CreateCredential();
            expiredAtNow.ExpiresAt = now;
            Assert.That(expiredAtNow.IsAvailable(now), Is.False);

            var activeWithFutureExpiry = CreateCredential();
            activeWithFutureExpiry.ExpiresAt = now.AddTicks(1);
            Assert.That(activeWithFutureExpiry.IsAvailable(now), Is.True);

            var activeWithRevocation = CreateCredential();
            activeWithRevocation.RevokedAt = now;
            Assert.That(activeWithRevocation.IsAvailable(now), Is.False);

            var nonActiveWithoutOtherLifecycleState = CreateCredential();
            nonActiveWithoutOtherLifecycleState.Status = CredentialStatus.Revoked;
            Assert.That(nonActiveWithoutOtherLifecycleState.IsAvailable(now), Is.False);

            var nonActiveWithRevocation = CreateCredential();
            nonActiveWithRevocation.Status = CredentialStatus.Revoked;
            nonActiveWithRevocation.RevokedAt = now;
            Assert.That(nonActiveWithRevocation.IsAvailable(now), Is.False);
        }
    }

    [Test]
    public void UserCredentialCloneShouldCopyCredentialState()
    {
        var credential = CreateCredential();
        credential.UpdatedAt = DateTimeOffset.UtcNow.AddHours(-3);
        credential.ExpiresAt = DateTimeOffset.UtcNow.AddHours(3);
        credential.RevokedAt = DateTimeOffset.UtcNow.AddHours(-1);
        credential.Status = CredentialStatus.Revoked;
        credential.Purpose = "recovery";
        credential.CredentialValue = "value";
        credential.LastUsedAt = DateTimeOffset.UtcNow.AddMinutes(-30);
        credential.Metadata = "{}";

        var clone = credential.Clone();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(clone, Is.Not.SameAs(credential));
            Assert.That(clone.Id, Is.EqualTo(credential.Id));
            Assert.That(clone.UserId, Is.EqualTo(credential.UserId));
            Assert.That(clone.ProviderType, Is.EqualTo(credential.ProviderType));
            Assert.That(clone.ProviderName, Is.EqualTo(credential.ProviderName));
            Assert.That(clone.ProviderKey, Is.EqualTo(credential.ProviderKey));
            Assert.That(clone.Version, Is.EqualTo(credential.Version));
            Assert.That(clone.CreatedAt, Is.EqualTo(credential.CreatedAt));
            Assert.That(clone.UpdatedAt, Is.EqualTo(credential.UpdatedAt));
            Assert.That(clone.ExpiresAt, Is.EqualTo(credential.ExpiresAt));
            Assert.That(clone.RevokedAt, Is.EqualTo(credential.RevokedAt));
            Assert.That(clone.Status, Is.EqualTo(credential.Status));
            Assert.That(clone.Purpose, Is.EqualTo(credential.Purpose));
            Assert.That(clone.CredentialValue, Is.EqualTo(credential.CredentialValue));
            Assert.That(clone.LastUsedAt, Is.EqualTo(credential.LastUsedAt));
            Assert.That(clone.Metadata, Is.EqualTo(credential.Metadata));
        }
    }

    [Test]
    public void SessionRevocationRequestPropertiesShouldWork()
    {
        var sessionId = Guid.NewGuid();
        var currentSessionId = Guid.NewGuid();
        var revokeRequest = new RevokeAuthenticationSessionRequest
        {
            SessionId = sessionId,
            Reason = "user-initiated",
            IpAddress = "127.0.0.1",
            UserAgent = "TestAgent"
        };
        var revokeOtherRequest = new RevokeOtherAuthenticationSessionsRequest
        {
            CurrentSessionId = currentSessionId,
            Reason = "security-cleanup",
            IpAddress = "127.0.0.2",
            UserAgent = "OtherAgent"
        };

        using (Assert.EnterMultipleScope())
        {
            Assert.That(revokeRequest.SessionId, Is.EqualTo(sessionId));
            Assert.That(revokeRequest.Reason, Is.EqualTo("user-initiated"));
            Assert.That(revokeRequest.IpAddress, Is.EqualTo("127.0.0.1"));
            Assert.That(revokeRequest.UserAgent, Is.EqualTo("TestAgent"));
            Assert.That(revokeOtherRequest.CurrentSessionId, Is.EqualTo(currentSessionId));
            Assert.That(revokeOtherRequest.Reason, Is.EqualTo("security-cleanup"));
            Assert.That(revokeOtherRequest.IpAddress, Is.EqualTo("127.0.0.2"));
            Assert.That(revokeOtherRequest.UserAgent, Is.EqualTo("OtherAgent"));
        }
    }

    private static UserCredential CreateCredential()
    {
        return new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Local,
            ProviderName = AuthenticationProviderKey.Local.Name,
            ProviderKey = "key",
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active
        };
    }
}
