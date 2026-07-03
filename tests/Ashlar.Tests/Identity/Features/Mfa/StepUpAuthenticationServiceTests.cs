using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Tests.Identity.Features.Mfa;

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
    public void CreateFreshMfaProofShouldScopeProofToFreshSession()
    {
        var service = CreateService();
        var tenantId = Guid.NewGuid();
        var session = CreateSession(
            tenantId: tenantId,
            additionalVerificationAt: _now.AddMinutes(-1),
            additionalVerificationProvider: TotpProvider(),
            additionalVerificationFactor: "totp");

        var result = service.CreateFreshMfaProof(new StepUpEvaluationRequest(
            session,
            new StepUpRequirement(TimeSpan.FromMinutes(10), [TotpProvider()], ["totp"])));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value!.UserId, Is.EqualTo(session.UserId));
            Assert.That(result.Value.TenantId, Is.EqualTo(tenantId));
            Assert.That(result.Value.SessionId, Is.EqualTo(session.Id));
            Assert.That(result.Value.VerifiedAt, Is.EqualTo(session.AdditionalVerificationAt));
            Assert.That(result.Value.ExpiresAt, Is.EqualTo(session.AdditionalVerificationAt!.Value.AddMinutes(10)));
        }
    }

    [Test]
    public void CreateFreshMfaProofShouldRejectStaleOrMissingVerification()
    {
        var service = CreateService();
        var stale = service.CreateFreshMfaProof(new StepUpEvaluationRequest(
            CreateSession(additionalVerificationAt: _now.AddMinutes(-11)),
            new StepUpRequirement(TimeSpan.FromMinutes(10))));
        var missing = service.CreateFreshMfaProof(new StepUpEvaluationRequest(
            CreateSession(),
            new StepUpRequirement(TimeSpan.FromMinutes(10))));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(stale.Succeeded, Is.False);
            Assert.That(stale.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpExpired));
            Assert.That(missing.Succeeded, Is.False);
            Assert.That(missing.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
        }
    }

    [Test]
    public void CreateFreshPrimaryAuthenticationProofShouldScopeProofToFreshSession()
    {
        var service = CreateService();
        var tenantId = Guid.NewGuid();
        var session = CreateSession(tenantId: tenantId, authenticatedAt: _now.AddMinutes(-1));

        var result = service.CreateFreshPrimaryAuthenticationProof(new PrimaryAuthenticationEvaluationRequest(session, TimeSpan.FromMinutes(10)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value!.UserId, Is.EqualTo(session.UserId));
            Assert.That(result.Value.TenantId, Is.EqualTo(tenantId));
            Assert.That(result.Value.SessionId, Is.EqualTo(session.Id));
            Assert.That(result.Value.AuthenticatedAt, Is.EqualTo(session.AuthenticatedAt));
            Assert.That(result.Value.ExpiresAt, Is.EqualTo(session.AuthenticatedAt!.Value.AddMinutes(10)));
        }
    }

    [Test]
    public void CreateFreshPrimaryAuthenticationProofShouldRejectMissingStaleOrInactiveSession()
    {
        var service = CreateService();
        var missing = service.CreateFreshPrimaryAuthenticationProof(new PrimaryAuthenticationEvaluationRequest(CreateSession(), TimeSpan.FromMinutes(10)));
        var stale = service.CreateFreshPrimaryAuthenticationProof(new PrimaryAuthenticationEvaluationRequest(CreateSession(authenticatedAt: _now.AddMinutes(-11)), TimeSpan.FromMinutes(10)));
        var future = service.CreateFreshPrimaryAuthenticationProof(new PrimaryAuthenticationEvaluationRequest(CreateSession(authenticatedAt: _now.AddMinutes(1)), TimeSpan.FromMinutes(10)));
        var inactive = service.CreateFreshPrimaryAuthenticationProof(new PrimaryAuthenticationEvaluationRequest(CreateSession(expiresAt: _now, authenticatedAt: _now.AddMinutes(-1)), TimeSpan.FromMinutes(10)));
        var missingSession = service.CreateFreshPrimaryAuthenticationProof(new PrimaryAuthenticationEvaluationRequest(null, TimeSpan.FromMinutes(10)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missing.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            Assert.That(stale.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpExpired));
            Assert.That(future.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpExpired));
            Assert.That(inactive.FailureCode, Is.EqualTo(AshlarFailureCodes.SessionNotFoundOrInactive));
            Assert.That(missingSession.FailureCode, Is.EqualTo(AshlarFailureCodes.SessionNotFoundOrInactive));
        }
    }

    [Test]
    public void CreateFreshPrimaryAuthenticationProofShouldRejectInvalidRequests()
    {
        var service = CreateService();

        Assert.Throws<ArgumentNullException>(() => service.CreateFreshPrimaryAuthenticationProof(null!));
        Assert.Throws<ArgumentOutOfRangeException>(() => service.CreateFreshPrimaryAuthenticationProof(new PrimaryAuthenticationEvaluationRequest(
            CreateSession(authenticatedAt: _now),
            TimeSpan.Zero)));
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
    public void EvaluateShouldFailForFutureAdditionalVerification()
    {
        var service = CreateService();
        var session = CreateSession(additionalVerificationAt: _now.AddMinutes(1));

        var result = service.Evaluate(new StepUpEvaluationRequest(session, new StepUpRequirement(TimeSpan.FromMinutes(10))));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpExpired));
    }

    [Test]
    public async Task MarkVerifiedAsyncShouldDelegateToSessionService()
    {
        var userId = Guid.NewGuid();
        var session = CreateSession();
        var request = new MarkSessionStepUpVerifiedRequest
        {
            SessionId = session.Id,
            VerifiedProvider = TotpProvider(),
            VerifiedFactor = "totp"
        };
        var sessionService = new Mock<IAuthenticationSessionService>();
        sessionService
            .Setup(s => s.MarkStepUpVerifiedAsync(userId, request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(session));
        var service = new StepUpAuthenticationService(sessionService.Object, new FakeTimeProvider(_now));

        var result = await service.MarkVerifiedAsync(userId, request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value, Is.EqualTo(session));
        }
    }

    [Test]
    public void MarkVerifiedAsyncShouldRequireSessionService()
    {
        var service = new StepUpAuthenticationService(new FakeTimeProvider(_now));

        Assert.ThrowsAsync<InvalidOperationException>(() => service.MarkVerifiedAsync(Guid.NewGuid(), new MarkSessionStepUpVerifiedRequest
        {
            SessionId = Guid.NewGuid(),
            VerifiedProvider = TotpProvider(),
            VerifiedFactor = "totp"
        }));
    }

    [Test]
    public void EvaluateShouldPassAfterSessionIsMarkedFreshAndFailAfterWindowExpires()
    {
        var timeProvider = new FakeTimeProvider(_now);
        var service = new StepUpAuthenticationService(timeProvider);
        var session = CreateSession();
        session.AdditionalVerificationAt = _now;
        session.AdditionalVerificationProvider = TotpProvider();
        session.AdditionalVerificationFactor = "totp";

        var fresh = service.Evaluate(new StepUpEvaluationRequest(session, new StepUpRequirement(TimeSpan.FromMinutes(10))));
        timeProvider.SetUtcNow(_now.AddMinutes(11));
        var expired = service.Evaluate(new StepUpEvaluationRequest(session, new StepUpRequirement(TimeSpan.FromMinutes(10))));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fresh.Succeeded, Is.True);
            Assert.That(expired.Succeeded, Is.False);
            Assert.That(expired.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpExpired));
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
    public void EvaluateShouldFailWhenAllowedProviderRequiresMissingVerificationProvider()
    {
        var service = CreateService();
        var session = CreateSession(additionalVerificationAt: _now.AddMinutes(-1), additionalVerificationFactor: "totp");

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
    public void EvaluateShouldFailWhenAllowedFactorRequiresMissingVerificationFactor()
    {
        var service = CreateService();
        var session = CreateSession(additionalVerificationAt: _now.AddMinutes(-1), additionalVerificationProvider: TotpProvider());

        var result = service.Evaluate(new StepUpEvaluationRequest(
            session,
            new StepUpRequirement(TimeSpan.FromMinutes(10), AllowedFactors: ["totp"])));

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
        Guid? tenantId = null,
        DateTimeOffset? authenticatedAt = null,
        DateTimeOffset? additionalVerificationAt = null,
        AuthenticationProviderKey? additionalVerificationProvider = null,
        string? additionalVerificationFactor = null)
    {
        return new AuthenticationSession
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            TenantId = tenantId,
            TokenHash = "hashed-token",
            CreatedAt = _now.AddHours(-1),
            AuthenticatedAt = authenticatedAt,
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
