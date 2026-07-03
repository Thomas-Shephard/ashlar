namespace Ashlar.Identity.Features.Mfa;

internal static class FreshVerificationProofValidator
{
    public static AshlarFailureCode? Validate(
        Guid userId,
        TenantContext tenant,
        FreshMfaVerificationProof? proof,
        Guid? currentSessionId,
        DateTimeOffset now)
    {
        if (proof == null)
        {
            return AshlarFailureCodes.StepUpRequired;
        }

        return Validate(userId, tenant, new FreshVerificationProofData(proof.UserId, proof.TenantId, proof.SessionId, proof.ExpiresAt), currentSessionId, now);
    }

    public static AshlarFailureCode? Validate(
        Guid userId,
        TenantContext tenant,
        FreshPrimaryAuthenticationProof? proof,
        Guid? currentSessionId,
        DateTimeOffset now)
    {
        if (proof == null)
        {
            return AshlarFailureCodes.StepUpRequired;
        }

        return Validate(userId, tenant, new FreshVerificationProofData(proof.UserId, proof.TenantId, proof.SessionId, proof.ExpiresAt), currentSessionId, now);
    }

    private static AshlarFailureCode? Validate(
        Guid userId,
        TenantContext tenant,
        FreshVerificationProofData proof,
        Guid? currentSessionId,
        DateTimeOffset now)
    {
        if (userId == Guid.Empty)
        {
            return AshlarFailureCodes.StepUpRequired;
        }

        if (proof.UserId != userId || proof.TenantId != tenant.TenantId)
        {
            return AshlarFailureCodes.TenantMismatch;
        }

        if (currentSessionId == null || proof.SessionId != currentSessionId.Value)
        {
            return AshlarFailureCodes.StepUpRequired;
        }

        return proof.ExpiresAt <= now ? AshlarFailureCodes.StepUpExpired : null;
    }

    private readonly record struct FreshVerificationProofData(Guid UserId, Guid? TenantId, Guid SessionId, DateTimeOffset ExpiresAt);
}
