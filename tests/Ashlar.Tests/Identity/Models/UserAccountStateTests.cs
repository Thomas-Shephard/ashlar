namespace Ashlar.Tests.Identity.Models;

[TestFixture]
internal sealed class UserAccountStateTests
{
    [TestCase(UserAccountState.Active, "active", true)]
    [TestCase(UserAccountState.Disabled, "disabled", false)]
    [TestCase(UserAccountState.Locked, "locked", false)]
    [TestCase(UserAccountState.Suspended, "suspended", false)]
    public void StateHelpersShouldUseStableStorageValuesAndSignInRules(UserAccountState state, string storageValue, bool canSignIn)
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(state.ToStorageValue(), Is.EqualTo(storageValue));
            Assert.That(UserAccountStates.FromStorageValue(storageValue), Is.EqualTo(state));
            Assert.That(state.CanSignIn(), Is.EqualTo(canSignIn));
        }
    }

    [TestCase(UserAccountState.Disabled, "user_disabled")]
    [TestCase(UserAccountState.Locked, "user_locked")]
    [TestCase(UserAccountState.Suspended, "user_suspended")]
    public void ToSecurityFailureReasonShouldReturnSafeReasonForUnavailableStates(UserAccountState state, string failureReason)
    {
        Assert.That(state.ToSecurityFailureReason(), Is.EqualTo(failureReason));
    }

    [Test]
    public void ToStorageValueShouldRejectUnknownState()
    {
        Assert.That(() => ((UserAccountState)999).ToStorageValue(), Throws.TypeOf<ArgumentOutOfRangeException>());
    }

    [Test]
    public void FromStorageValueShouldRejectUnknownValue()
    {
        Assert.That(() => UserAccountStates.FromStorageValue("unknown"), Throws.TypeOf<ArgumentOutOfRangeException>());
    }

    [Test]
    public void ToSecurityFailureReasonShouldRejectActiveState()
    {
        Assert.That(() => UserAccountState.Active.ToSecurityFailureReason(), Throws.TypeOf<InvalidOperationException>());
    }

    [Test]
    public void ToSecurityFailureReasonShouldReturnGenericReasonForUnknownState()
    {
        Assert.That(((UserAccountState)999).ToSecurityFailureReason(), Is.EqualTo("invalid_credentials"));
    }
}
