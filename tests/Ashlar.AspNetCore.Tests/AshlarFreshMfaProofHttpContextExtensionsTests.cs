using Ashlar.AspNetCore.Authentication;
using Ashlar.AspNetCore.Mfa;
using Microsoft.AspNetCore.Http;

namespace Ashlar.AspNetCore.Tests;

[TestFixture]
internal sealed class AshlarFreshMfaProofHttpContextExtensionsTests
{
    private static readonly DateTimeOffset Now = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public void CreateFreshMfaProofShouldReturnFailureWhenSessionItemIsMissing()
    {
        var result = new DefaultHttpContext().CreateFreshMfaProof(
            new StepUpAuthenticationService(new FakeTimeProvider(Now)),
            new StepUpRequirement(TimeSpan.FromMinutes(10)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.SessionNotFoundOrInactive));
        }
    }

    [Test]
    public void CreateFreshMfaProofShouldUseValidatedSessionItem()
    {
        var session = new AuthenticationSession
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            TenantId = Guid.NewGuid(),
            TokenHash = "hash",
            CreatedAt = Now.AddMinutes(-10),
            ExpiresAt = Now.AddMinutes(10),
            AdditionalVerificationAt = Now.AddMinutes(-1),
            AdditionalVerificationProvider = new AuthenticationProviderKey(ProviderType.Mfa, "totp"),
            AdditionalVerificationFactor = AuthenticationFactorTypes.Totp
        };
        var context = new DefaultHttpContext();
        context.Items[AshlarHttpContextItems.ValidatedAuthenticationSession] = CreateValidatedSession(session);

        var result = context.CreateFreshMfaProof(
            new StepUpAuthenticationService(new FakeTimeProvider(Now)),
            new StepUpRequirement(TimeSpan.FromMinutes(10)));

        Assert.That(result.Value?.SessionId, Is.EqualTo(session.Id));
    }

    [Test]
    public void CreateFreshMfaProofShouldRejectManualSessionItem()
    {
        var context = new DefaultHttpContext();
        context.Items[AshlarHttpContextItems.AuthenticationSession] = new AuthenticationSession
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            TokenHash = "manual",
            CreatedAt = Now,
            ExpiresAt = Now.AddHours(1)
        };

        var result = context.CreateFreshMfaProof(new StepUpAuthenticationService(new FakeTimeProvider(Now)),
            new StepUpRequirement(TimeSpan.FromMinutes(10)));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.SessionNotFoundOrInactive));
    }

    [Test]
    public void CreateFreshPrimaryAuthenticationProofShouldReturnFailureWhenSessionItemIsMissing()
    {
        var result = new DefaultHttpContext().CreateFreshPrimaryAuthenticationProof(
            new StepUpAuthenticationService(new FakeTimeProvider(Now)),
            TimeSpan.FromMinutes(10));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.SessionNotFoundOrInactive));
    }

    [Test]
    public void CreateFreshPrimaryAuthenticationProofShouldUseValidatedSessionItem()
    {
        var session = new AuthenticationSession
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            TenantId = Guid.NewGuid(),
            TokenHash = "hash",
            CreatedAt = Now.AddMinutes(-10),
            AuthenticatedAt = Now.AddMinutes(-1),
            ExpiresAt = Now.AddMinutes(10)
        };
        var context = new DefaultHttpContext();
        context.Items[AshlarHttpContextItems.ValidatedAuthenticationSession] = CreateValidatedSession(session);

        var result = context.CreateFreshPrimaryAuthenticationProof(
            new StepUpAuthenticationService(new FakeTimeProvider(Now)),
            TimeSpan.FromMinutes(10),
            "passkey-registration");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value?.SessionId, Is.EqualTo(session.Id));
            Assert.That(result.Value?.Purpose, Is.EqualTo("passkey-registration"));
        }
    }

    private sealed class FakeTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private static ValidatedAuthenticationSession CreateValidatedSession(AuthenticationSession session) =>
        (ValidatedAuthenticationSession)Activator.CreateInstance(typeof(ValidatedAuthenticationSession),
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic, null, [session], null)!;
}
