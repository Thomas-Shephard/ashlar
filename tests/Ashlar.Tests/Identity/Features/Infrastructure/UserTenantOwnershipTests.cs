namespace Ashlar.Tests.Identity.Features.Infrastructure;

internal sealed class UserTenantOwnershipTests
{
    [Test]
    public void MatchesShouldTreatNonTenantUserAsGlobal()
    {
        var user = new NonTenantUser(Guid.NewGuid());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(UserTenantOwnership.Matches(user, null), Is.True);
            Assert.That(UserTenantOwnership.Matches(user, Guid.NewGuid()), Is.False);
        }
    }

    [Test]
    public void MatchesShouldCompareTenantUserTenant()
    {
        var tenantId = Guid.NewGuid();
        var user = new TenantUser(Guid.NewGuid(), tenantId);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(UserTenantOwnership.Matches(user, tenantId), Is.True);
            Assert.That(UserTenantOwnership.Matches(user, null), Is.False);
            Assert.That(UserTenantOwnership.Matches(user, Guid.NewGuid()), Is.False);
        }
    }

    private sealed record NonTenantUser(Guid Id) : IUser
    {
        public string DisplayEmail => $"{Id:N}@example.com";
        public string? Name => null;
        public UserAccountState AccountState => UserAccountState.Active;
        public DateTimeOffset? EmailVerifiedAt => null;
    }

    private sealed record TenantUser(Guid Id, Guid? TenantId) : ITenantUser
    {
        public string DisplayEmail => $"{Id:N}@example.com";
        public string? Name => null;
        public UserAccountState AccountState => UserAccountState.Active;
        public DateTimeOffset? EmailVerifiedAt => null;
    }
}
