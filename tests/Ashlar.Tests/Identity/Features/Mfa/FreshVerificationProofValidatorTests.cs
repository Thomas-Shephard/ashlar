namespace Ashlar.Tests.Identity.Features.Mfa;

internal sealed class FreshVerificationProofValidatorTests
{
    private readonly DateTimeOffset _now = new(2026, 5, 17, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public void ValidateShouldRejectEmptyTargetUser()
    {
        var proof = new FreshMfaVerificationProof(
            Guid.NewGuid(),
            tenantId: null,
            Guid.NewGuid(),
            _now,
            _now.AddMinutes(10));

        var failure = FreshVerificationProofValidator.ValidateMfaProof(Guid.Empty, TenantContext.Global, proof, proof.SessionId, _now);

        Assert.That(failure, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
    }

    [Test]
    public void ValidateShouldRejectSameUserProofForDifferentTenant()
    {
        var userId = Guid.NewGuid();
        var proof = new FreshPrimaryAuthenticationProof(
            userId,
            Guid.NewGuid(),
            Guid.NewGuid(),
            _now,
            _now.AddMinutes(10));

        var failure = FreshVerificationProofValidator.ValidatePrimaryAuthenticationProof(userId, TenantContext.Global, proof, proof.SessionId, _now);

        Assert.That(failure, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
    }

    [Test]
    public void ValidateShouldRejectMissingCurrentSessionId()
    {
        var userId = Guid.NewGuid();
        var proof = new FreshMfaVerificationProof(
            userId,
            tenantId: null,
            Guid.NewGuid(),
            _now,
            _now.AddMinutes(10));

        var failure = FreshVerificationProofValidator.ValidateMfaProof(userId, TenantContext.Global, proof, currentSessionId: null, _now);

        Assert.That(failure, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
    }

    [Test]
    public void ValidateShouldRejectWrongPurposeWhenRequired()
    {
        var userId = Guid.NewGuid();
        var proof = new FreshPrimaryAuthenticationProof(
            userId,
            tenantId: null,
            Guid.NewGuid(),
            _now,
            _now.AddMinutes(10),
            "totp-enrollment");

        var failure = FreshVerificationProofValidator.ValidatePrimaryAuthenticationProof(userId, TenantContext.Global, proof, proof.SessionId, _now, "passkey-registration");

        Assert.That(failure, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
    }
}

