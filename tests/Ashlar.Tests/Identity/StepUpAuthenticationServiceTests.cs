using Ashlar.Identity;
using Ashlar.Identity.Models;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Tests.Identity;

internal sealed class StepUpAuthenticationServiceTests
{
    private readonly DateTimeOffset _now = new(2026, 5, 17, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public void EvaluateShouldRequireAdditionalVerificationForDefaultSession()
    {
        var service = CreateService();
        var session = CreateSession();

        var result = service.Evaluate(new StepUpEvaluationRequest(session, new StepUpRequirement(TimeSpan.FromMinutes(10))));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
        }
    }

    [Test]
    public void EvaluateShouldPassForRecentAdditionalVerification()
    {
        var service = CreateService();
        var session = CreateSession(additionalVerificationAt: _now.AddMinutes(-5), additionalVerificationProvider: TotpProvider(), additionalVerificationFactor: "totp");

        var result = service.Evaluate(new StepUpEvaluationRequest(
            session,
            new StepUpRequirement(TimeSpan.FromMinutes(10), [TotpProvider()], ["totp"])));

        Assert.That(result.Succeeded, Is.True);
    }

    [Test]
    public void EvaluateShouldFailForExpiredAdditionalVerification()
    {
        var service = CreateService();
        var session = CreateSession(additionalVerificationAt: _now.AddMinutes(-11), additionalVerificationProvider: TotpProvider(), additionalVerificationFactor: "totp");

        var result = service.Evaluate(new StepUpEvaluationRequest(session, new StepUpRequirement(TimeSpan.FromMinutes(10))));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpExpired));
        }
    }

    [Test]
    public void EvaluateShouldFailForDisallowedProvider()
    {
        var service = CreateService();
        var session = CreateSession(additionalVerificationAt: _now.AddMinutes(-1), additionalVerificationProvider: TotpProvider(), additionalVerificationFactor: "totp");

        var result = service.Evaluate(new StepUpEvaluationRequest(
            session,
            new StepUpRequirement(TimeSpan.FromMinutes(10), [AuthenticationProviderKey.Passkey])));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpProviderNotAllowed));
    }

    [Test]
    public void EvaluateShouldFailForDisallowedFactor()
    {
        var service = CreateService();
        var session = CreateSession(additionalVerificationAt: _now.AddMinutes(-1), additionalVerificationProvider: TotpProvider(), additionalVerificationFactor: "totp");

        var result = service.Evaluate(new StepUpEvaluationRequest(
            session,
            new StepUpRequirement(TimeSpan.FromMinutes(10), AllowedFactors: ["passkey"])));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpFactorNotAllowed));
    }

    [Test]
    public void EvaluateShouldFailForMissingOrInactiveSession()
    {
        var service = CreateService();
        var result = service.Evaluate(new StepUpEvaluationRequest(null, new StepUpRequirement(TimeSpan.FromMinutes(10))));
        var expired = service.Evaluate(new StepUpEvaluationRequest(CreateSession(expiresAt: _now), new StepUpRequirement(TimeSpan.FromMinutes(10))));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.SessionNotFoundOrInactive));
            Assert.That(expired.FailureCode, Is.EqualTo(AshlarFailureCodes.SessionNotFoundOrInactive));
        }
    }

    [Test]
    public void EvaluateShouldRejectInvalidRequests()
    {
        var service = new StepUpAuthenticationService();

        Assert.Throws<ArgumentNullException>(() => service.Evaluate(null!));
        Assert.Throws<ArgumentOutOfRangeException>(() => service.Evaluate(new StepUpEvaluationRequest(
            CreateSession(),
            new StepUpRequirement(TimeSpan.Zero))));
    }

    private StepUpAuthenticationService CreateService()
    {
        return new StepUpAuthenticationService(new FakeTimeProvider(_now));
    }

    private AuthenticationSession CreateSession(
        DateTimeOffset? expiresAt = null,
        DateTimeOffset? additionalVerificationAt = null,
        AuthenticationProviderKey? additionalVerificationProvider = null,
        string? additionalVerificationFactor = null)
    {
        return new AuthenticationSession
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            TokenHash = "hashed-token",
            CreatedAt = _now.AddHours(-1),
            ExpiresAt = expiresAt ?? _now.AddHours(1),
            AdditionalVerificationAt = additionalVerificationAt,
            AdditionalVerificationProvider = additionalVerificationProvider,
            AdditionalVerificationFactor = additionalVerificationFactor
        };
    }

    private static AuthenticationProviderKey TotpProvider()
    {
        return new AuthenticationProviderKey(ProviderType.Mfa, "totp");
    }
}
