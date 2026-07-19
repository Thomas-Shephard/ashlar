using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Tests.Identity.Features.Mfa;

internal sealed class ActiveSessionFreshProofValidatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Test]
    public void ConstructorShouldRejectNullDependencies()
    {
        var repository = Mock.Of<IAuthenticationSessionRepository>();

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new ActiveSessionFreshProofValidator(null!, TimeProvider.System));
            Assert.Throws<ArgumentNullException>(() => _ = new ActiveSessionFreshProofValidator(repository, null!));
        }
    }

    [Test]
    public async Task ValidateAsyncShouldRejectEmptyTargetUser()
    {
        var proof = new FreshMfaVerificationProof(Guid.NewGuid(), null, Guid.NewGuid(), Now, Now.AddMinutes(10), "purpose");

        var failure = await Validator().ValidateAsync(Guid.Empty, TenantContext.Global, proof, proof.SessionId, "purpose", CancellationToken.None);

        Assert.That(failure, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
    }

    [Test]
    public async Task ValidateAsyncShouldRejectDifferentTenant()
    {
        var userId = Guid.NewGuid();
        var proof = new FreshPrimaryAuthenticationProof(userId, Guid.NewGuid(), Guid.NewGuid(), Now, Now.AddMinutes(10), "purpose");

        var failure = await Validator().ValidateAsync(userId, TenantContext.Global, proof, proof.SessionId, "purpose", CancellationToken.None);

        Assert.That(failure, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
    }

    [Test]
    public async Task ValidateAsyncShouldRejectMissingCurrentSession()
    {
        var userId = Guid.NewGuid();
        var proof = new FreshMfaVerificationProof(userId, null, Guid.NewGuid(), Now, Now.AddMinutes(10), "purpose");

        var failure = await Validator().ValidateAsync(userId, TenantContext.Global, proof, null, "purpose", CancellationToken.None);

        Assert.That(failure, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
    }

    [Test]
    public async Task ValidateAsyncShouldRejectWrongPurpose()
    {
        var userId = Guid.NewGuid();
        var proof = new FreshPrimaryAuthenticationProof(userId, null, Guid.NewGuid(), Now, Now.AddMinutes(10), "totp-enrollment");

        var failure = await Validator().ValidateAsync(userId, TenantContext.Global, proof, proof.SessionId, "passkey-registration", CancellationToken.None);

        Assert.That(failure, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
    }

    [TestCase("missing")]
    [TestCase("revoked")]
    [TestCase("expired")]
    [TestCase("user")]
    [TestCase("tenant")]
    public async Task ValidateAsyncShouldRejectInactiveOrMismatchedSourceSession(string problem)
    {
        var userId = Guid.NewGuid();
        var tenant = new TenantContext(Guid.NewGuid());
        var sessionId = Guid.NewGuid();
        var proof = new FreshMfaVerificationProof(userId, tenant.TenantId, sessionId, Now, Now.AddMinutes(5), "purpose");
        var repository = new Mock<IAuthenticationSessionRepository>();
        if (problem != "missing")
        {
            repository.Setup(r => r.GetSessionAsync(sessionId, It.IsAny<CancellationToken>())).ReturnsAsync(new AuthenticationSession
            {
                Id = sessionId,
                UserId = problem == "user" ? Guid.NewGuid() : userId,
                TenantId = problem == "tenant" ? Guid.NewGuid() : tenant.TenantId,
                TokenHash = "hash",
                CreatedAt = Now.AddHours(-1),
                ExpiresAt = problem == "expired" ? Now : Now.AddHours(1),
                RevokedAt = problem == "revoked" ? Now : null
            });
        }

        var failure = await new ActiveSessionFreshProofValidator(repository.Object, new FakeTimeProvider(Now))
            .ValidateAsync(userId, tenant, proof, sessionId, "purpose", CancellationToken.None);

        Assert.That(failure, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
    }

    [Test]
    public async Task ValidateAsyncShouldAcceptActiveMatchingSourceSession()
    {
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var proof = new FreshPrimaryAuthenticationProof(userId, null, sessionId, Now, Now.AddMinutes(5), "purpose");
        var repository = new Mock<IAuthenticationSessionRepository>();
        repository.Setup(r => r.GetSessionAsync(sessionId, It.IsAny<CancellationToken>())).ReturnsAsync(new AuthenticationSession
        {
            Id = sessionId,
            UserId = userId,
            TokenHash = "hash",
            CreatedAt = Now.AddHours(-1),
            ExpiresAt = Now.AddHours(1)
        });

        var failure = await new ActiveSessionFreshProofValidator(repository.Object, new FakeTimeProvider(Now))
            .ValidateAsync(userId, TenantContext.Global, proof, sessionId, "purpose", CancellationToken.None);

        Assert.That(failure, Is.Null);
    }

    [Test]
    public async Task ValidateAsyncShouldRecheckExpiryAfterSessionLookup()
    {
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var clock = new FakeTimeProvider(Now);
        var proof = new FreshMfaVerificationProof(userId, null, sessionId, Now, Now.AddSeconds(1), "purpose");
        var repository = new Mock<IAuthenticationSessionRepository>();
        repository.Setup(r => r.GetSessionAsync(sessionId, It.IsAny<CancellationToken>()))
            .Callback(() => clock.Advance(TimeSpan.FromSeconds(2)))
            .ReturnsAsync(new AuthenticationSession
            {
                Id = sessionId,
                UserId = userId,
                TokenHash = "hash",
                CreatedAt = Now.AddHours(-1),
                ExpiresAt = Now.AddHours(1)
            });

        var failure = await new ActiveSessionFreshProofValidator(repository.Object, clock)
            .ValidateAsync(userId, TenantContext.Global, proof, sessionId, "purpose", CancellationToken.None);

        Assert.That(failure, Is.EqualTo(AshlarFailureCodes.StepUpExpired));
    }

    [Test]
    public async Task PrimaryValidateAsyncShouldRecheckExpiryAfterSessionLookup()
    {
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var clock = new FakeTimeProvider(Now);
        var proof = new FreshPrimaryAuthenticationProof(userId, null, sessionId, Now, Now.AddSeconds(1), "purpose");
        var repository = new Mock<IAuthenticationSessionRepository>();
        repository.Setup(r => r.GetSessionAsync(sessionId, It.IsAny<CancellationToken>()))
            .Callback(() => clock.Advance(TimeSpan.FromSeconds(2)))
            .ReturnsAsync(new AuthenticationSession
            {
                Id = sessionId,
                UserId = userId,
                TokenHash = "hash",
                CreatedAt = Now.AddHours(-1),
                ExpiresAt = Now.AddHours(1)
            });

        var failure = await new ActiveSessionFreshProofValidator(repository.Object, clock)
            .ValidateAsync(userId, TenantContext.Global, proof, sessionId, "purpose", CancellationToken.None);

        Assert.That(failure, Is.EqualTo(AshlarFailureCodes.StepUpExpired));
    }

    private static ActiveSessionFreshProofValidator Validator() =>
        new(Mock.Of<IAuthenticationSessionRepository>(), new FakeTimeProvider(Now));
}
