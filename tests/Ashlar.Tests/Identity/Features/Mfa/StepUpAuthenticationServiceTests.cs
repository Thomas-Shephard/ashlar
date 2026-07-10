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
    public void PublicApiShouldNotMintProofsFromManualSessions()
    {
        using var _ = Assert.EnterMultipleScope();
        Assert.That(typeof(ValidatedAuthenticationSession).GetConstructors(), Is.Empty);
        Assert.That(typeof(ValidatedAuthenticationSession).GetProperties(),
            Has.Some.Matches<System.Reflection.PropertyInfo>(property => property.Name == nameof(ValidatedAuthenticationSession.UserId) && property.GetMethod?.IsPublic == true));
        Assert.That(typeof(IStepUpAuthenticationService).GetMethods()
            .Where(method => method.Name.StartsWith("CreateFresh", StringComparison.Ordinal))
            .SelectMany(method => method.GetParameters()),
            Has.None.Matches<System.Reflection.ParameterInfo>(parameter =>
                parameter.ParameterType == typeof(AuthenticationSession)
                || parameter.ParameterType == typeof(StepUpEvaluationRequest)));
    }

    [Test]
    public void ValidatedSessionShouldSnapshotFreshnessPosture()
    {
        var session = CreateSession();
        var validatedSession = new ValidatedAuthenticationSession(session);
        session.AdditionalVerificationAt = _now;

        var result = CreateService().CreateFreshMfaProof(validatedSession, new StepUpRequirement(TimeSpan.FromMinutes(10)));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
    }

    [Test]
    public void FreshnessBoundaryShouldBeExpiredEverywhere()
    {
        var session = CreateSession(authenticatedAt: _now.AddMinutes(-10), additionalVerificationAt: _now.AddMinutes(-10));
        var validatedSession = new ValidatedAuthenticationSession(session);
        var service = CreateService();

        using var _ = Assert.EnterMultipleScope();
        Assert.That(service.Evaluate(new StepUpEvaluationRequest(session, new StepUpRequirement(TimeSpan.FromMinutes(10)))).FailureCode,
            Is.EqualTo(AshlarFailureCodes.StepUpExpired));
        Assert.That(service.CreateFreshMfaProof(validatedSession, new StepUpRequirement(TimeSpan.FromMinutes(10))).FailureCode,
            Is.EqualTo(AshlarFailureCodes.StepUpExpired));
        Assert.That(service.CreateFreshPrimaryAuthenticationProof(validatedSession, TimeSpan.FromMinutes(10)).FailureCode,
            Is.EqualTo(AshlarFailureCodes.StepUpExpired));
    }

    [Test]
    public void ProofExpiryShouldCapHugeWindowsWithoutOverflow()
    {
        var session = CreateSession(authenticatedAt: _now, additionalVerificationAt: _now);
        var validatedSession = new ValidatedAuthenticationSession(session);
        var service = CreateService();

        using var _ = Assert.EnterMultipleScope();
        Assert.That(service.CreateFreshMfaProof(validatedSession, new StepUpRequirement(TimeSpan.MaxValue)).Value?.ExpiresAt,
            Is.EqualTo(session.ExpiresAt));
        Assert.That(service.CreateFreshPrimaryAuthenticationProof(validatedSession, TimeSpan.MaxValue).Value?.ExpiresAt,
            Is.EqualTo(session.ExpiresAt));
    }

    [Test]
    public void ProofExpiryShouldHandleExtremeOffsets()
    {
        var ceremonyAt = new DateTimeOffset(DateTime.MaxValue.AddMinutes(-10), TimeSpan.FromHours(14));
        var session = CreateSession(
            expiresAt: ceremonyAt.ToUniversalTime().AddMinutes(30),
            authenticatedAt: ceremonyAt,
            additionalVerificationAt: ceremonyAt);
        var validatedSession = new ValidatedAuthenticationSession(session);
        var service = new StepUpAuthenticationService(new FakeTimeProvider(ceremonyAt));

        using var _ = Assert.EnterMultipleScope();
        Assert.That(service.CreateFreshMfaProof(validatedSession, new StepUpRequirement(TimeSpan.FromMinutes(20))).Value?.ExpiresAt,
            Is.EqualTo(ceremonyAt.ToUniversalTime().AddMinutes(20)));
        Assert.That(service.CreateFreshPrimaryAuthenticationProof(validatedSession, TimeSpan.FromMinutes(20)).Value?.ExpiresAt,
            Is.EqualTo(ceremonyAt.ToUniversalTime().AddMinutes(20)));
    }

    [Test]
    public void CreateFreshMfaProofShouldScopeProofToFreshSession()
    {
        var service = CreateService();
        var tenantId = Guid.NewGuid();
        var session = CreateSession(
            expiresAt: _now.AddMinutes(3),
            tenantId: tenantId,
            additionalVerificationAt: _now.AddMinutes(-1),
            additionalVerificationProvider: TotpProvider(),
            additionalVerificationFactor: "totp");

        var result = service.CreateFreshMfaProof(new ValidatedAuthenticationSession(session),
            new StepUpRequirement(TimeSpan.FromMinutes(10), [TotpProvider()], ["totp"], "passkey-registration"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value!.UserId, Is.EqualTo(session.UserId));
            Assert.That(result.Value.TenantId, Is.EqualTo(tenantId));
            Assert.That(result.Value.SessionId, Is.EqualTo(session.Id));
            Assert.That(result.Value.VerifiedAt, Is.EqualTo(session.AdditionalVerificationAt));
            Assert.That(result.Value.ExpiresAt, Is.EqualTo(session.ExpiresAt));
            Assert.That(result.Value.Purpose, Is.EqualTo("passkey-registration"));
        }
    }

    [Test]
    public void CreateFreshMfaProofShouldRejectStaleOrMissingVerification()
    {
        var service = CreateService();
        var stale = service.CreateFreshMfaProof(new ValidatedAuthenticationSession(CreateSession(additionalVerificationAt: _now.AddMinutes(-11))),
            new StepUpRequirement(TimeSpan.FromMinutes(10)));
        var missing = service.CreateFreshMfaProof(new ValidatedAuthenticationSession(CreateSession()),
            new StepUpRequirement(TimeSpan.FromMinutes(10)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(stale.Succeeded, Is.False);
            Assert.That(stale.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpExpired));
            Assert.That(missing.Succeeded, Is.False);
            Assert.That(missing.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
        }
    }

    [Test]
    public void CreateFreshMfaProofShouldRejectInvalidRequirementOrInactiveSession()
    {
        var service = CreateService();
        using var _ = Assert.EnterMultipleScope();

        Assert.Throws<ArgumentOutOfRangeException>(() => service.CreateFreshMfaProof(
            new ValidatedAuthenticationSession(CreateSession(additionalVerificationAt: _now)),
            new StepUpRequirement(TimeSpan.Zero)));

        var inactive = service.CreateFreshMfaProof(
            new ValidatedAuthenticationSession(CreateSession(expiresAt: _now, additionalVerificationAt: _now.AddMinutes(-1))),
            new StepUpRequirement(TimeSpan.FromMinutes(10)));

        Assert.That(inactive.FailureCode, Is.EqualTo(AshlarFailureCodes.SessionNotFoundOrInactive));
    }

    [Test]
    public void CreateFreshPrimaryAuthenticationProofShouldScopeProofToFreshSession()
    {
        var service = CreateService();
        var tenantId = Guid.NewGuid();
        var session = CreateSession(expiresAt: _now.AddMinutes(3), tenantId: tenantId, authenticatedAt: _now.AddMinutes(-1));

        var result = service.CreateFreshPrimaryAuthenticationProof(new ValidatedAuthenticationSession(session), TimeSpan.FromMinutes(10), "passkey-registration");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value!.UserId, Is.EqualTo(session.UserId));
            Assert.That(result.Value.TenantId, Is.EqualTo(tenantId));
            Assert.That(result.Value.SessionId, Is.EqualTo(session.Id));
            Assert.That(result.Value.AuthenticatedAt, Is.EqualTo(session.AuthenticatedAt));
            Assert.That(result.Value.ExpiresAt, Is.EqualTo(session.ExpiresAt));
            Assert.That(result.Value.Purpose, Is.EqualTo("passkey-registration"));
        }
    }

    [Test]
    public void CreateFreshPrimaryAuthenticationProofShouldRejectMissingStaleOrInactiveSession()
    {
        var service = CreateService();
        var missing = service.CreateFreshPrimaryAuthenticationProof(new ValidatedAuthenticationSession(CreateSession()), TimeSpan.FromMinutes(10));
        var stale = service.CreateFreshPrimaryAuthenticationProof(new ValidatedAuthenticationSession(CreateSession(authenticatedAt: _now.AddMinutes(-11))), TimeSpan.FromMinutes(10));
        var future = service.CreateFreshPrimaryAuthenticationProof(new ValidatedAuthenticationSession(CreateSession(authenticatedAt: _now.AddMinutes(1))), TimeSpan.FromMinutes(10));
        var inactive = service.CreateFreshPrimaryAuthenticationProof(new ValidatedAuthenticationSession(CreateSession(expiresAt: _now, authenticatedAt: _now.AddMinutes(-1))), TimeSpan.FromMinutes(10));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missing.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            Assert.That(stale.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpExpired));
            Assert.That(future.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpExpired));
            Assert.That(inactive.FailureCode, Is.EqualTo(AshlarFailureCodes.SessionNotFoundOrInactive));
        }
    }

    [Test]
    public void CreateFreshPrimaryAuthenticationProofShouldRejectInvalidRequests()
    {
        var service = CreateService();

        Assert.Throws<ArgumentNullException>(() => service.CreateFreshPrimaryAuthenticationProof(null!, TimeSpan.FromMinutes(10)));
        Assert.Throws<ArgumentOutOfRangeException>(() => service.CreateFreshPrimaryAuthenticationProof(
            new ValidatedAuthenticationSession(CreateSession(authenticatedAt: _now)), TimeSpan.Zero));
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
            .Setup(s => s.MarkStepUpVerifiedAsync(It.IsAny<MfaAuthenticationResult>(), request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(session));
        var service = new StepUpAuthenticationService(sessionService.Object, new FakeTimeProvider(_now));

        var result = await service.MarkVerifiedAsync(CreateStepUpResult(userId), request);

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

        Assert.ThrowsAsync<InvalidOperationException>(() => service.MarkVerifiedAsync(CreateStepUpResult(Guid.NewGuid()), new MarkSessionStepUpVerifiedRequest
        {
            SessionId = Guid.NewGuid(),
            VerifiedProvider = TotpProvider(),
            VerifiedFactor = "totp"
        }));
    }

    [Test]
    public void MarkVerifiedAsyncShouldRequireSessionServiceForAuthenticationResponse()
    {
        var service = new StepUpAuthenticationService(new FakeTimeProvider(_now));

        Assert.ThrowsAsync<InvalidOperationException>(() => service.MarkVerifiedAsync(CreateStepUpResponse(Guid.NewGuid()), new MarkSessionStepUpVerifiedRequest
        {
            SessionId = Guid.NewGuid(),
            VerifiedProvider = TotpProvider(),
            VerifiedFactor = "totp"
        }));
    }

    [Test]
    public async Task MarkVerifiedAsyncShouldRejectAuthenticationResponseWithoutAshlarStepUpProof()
    {
        var sessionService = new Mock<IAuthenticationSessionService>();
        var service = new StepUpAuthenticationService(sessionService.Object, new FakeTimeProvider(_now));
        var request = new MarkSessionStepUpVerifiedRequest
        {
            SessionId = Guid.NewGuid(),
            VerifiedProvider = TotpProvider(),
            VerifiedFactor = "totp"
        };
        var missingProof = new AuthenticationResponse(true, new User { Id = Guid.NewGuid(), DisplayEmail = "user@example.com" }, AuthenticationStatus.Success, null);
        var missingUser = new AuthenticationResponse(true, null, AuthenticationStatus.Success, null)
        {
            StepUpSessionMarkingProof = StepUpSessionMarkingProof.Instance
        };
        var emptyUserId = new AuthenticationResponse(true, new User { Id = Guid.Empty, DisplayEmail = "user@example.com" }, AuthenticationStatus.Success, null)
        {
            StepUpSessionMarkingProof = StepUpSessionMarkingProof.Instance
        };
        var failed = new AuthenticationResponse(false, new User { Id = Guid.NewGuid(), DisplayEmail = "user@example.com" }, AuthenticationStatus.Failed, null)
        {
            StepUpSessionMarkingProof = StepUpSessionMarkingProof.Instance
        };

        var missingProofResult = await service.MarkVerifiedAsync(missingProof, request);
        var missingUserResult = await service.MarkVerifiedAsync(missingUser, request);
        var emptyUserIdResult = await service.MarkVerifiedAsync(emptyUserId, request);
        var failedResult = await service.MarkVerifiedAsync(failed, request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missingProofResult.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            Assert.That(missingUserResult.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            Assert.That(emptyUserIdResult.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            Assert.That(failedResult.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            sessionService.Verify(s => s.MarkStepUpVerifiedAsync(It.IsAny<MfaAuthenticationResult>(), It.IsAny<MarkSessionStepUpVerifiedRequest>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task MarkVerifiedAsyncShouldConvertAuthenticationResponseToStepUpResult()
    {
        var userId = Guid.NewGuid();
        var session = CreateSession();
        MfaAuthenticationResult? capturedResult = null;
        var request = new MarkSessionStepUpVerifiedRequest
        {
            SessionId = session.Id,
            VerifiedProvider = TotpProvider(),
            VerifiedFactor = "totp"
        };
        var sessionService = new Mock<IAuthenticationSessionService>();
        sessionService
            .Setup(s => s.MarkStepUpVerifiedAsync(It.IsAny<MfaAuthenticationResult>(), request, It.IsAny<CancellationToken>()))
            .Callback<MfaAuthenticationResult, MarkSessionStepUpVerifiedRequest, CancellationToken>((result, _, _) => capturedResult = result)
            .ReturnsAsync(Result.Success(session));
        var service = new StepUpAuthenticationService(sessionService.Object, new FakeTimeProvider(_now));

        var mark = await service.MarkVerifiedAsync(CreateStepUpResponse(userId), request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(mark.Succeeded, Is.True);
            Assert.That(capturedResult?.User?.Id, Is.EqualTo(userId));
            Assert.That(capturedResult?.FreshMfaSatisfied, Is.True);
        }
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

    private static MfaAuthenticationResult CreateStepUpResult(Guid userId)
    {
        return new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, new User { Id = userId, DisplayEmail = "user@example.com" }, FreshMfaSatisfied: true)
        {
            StepUpSessionMarkingProof = StepUpSessionMarkingProof.Instance
        };
    }

    private static AuthenticationResponse CreateStepUpResponse(Guid userId)
    {
        return new AuthenticationResponse(true, new User { Id = userId, DisplayEmail = "user@example.com" }, AuthenticationStatus.Success, null)
        {
            StepUpSessionMarkingProof = StepUpSessionMarkingProof.Instance
        };
    }
}
