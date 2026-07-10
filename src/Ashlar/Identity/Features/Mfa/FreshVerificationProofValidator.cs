namespace Ashlar.Identity.Features.Mfa;

/// <summary>
/// Validates Ashlar fresh-verification capability objects against a target user, tenant, and current session.
/// </summary>
public static class FreshVerificationProofValidator
{
    /// <summary>
    /// Validates a fresh MFA proof for a self-service operation.
    /// </summary>
    /// <param name="userId">The target user that must own the proof.</param>
    /// <param name="tenant">The target tenant scope that must match the proof.</param>
    /// <param name="proof">The proof returned by <see cref="StepUpAuthenticationService.CreateFreshMfaProof" />.</param>
    /// <param name="currentSessionId">The current Ashlar session id from the authenticated request.</param>
    /// <param name="now">Current UTC time.</param>
    /// <param name="requiredPurpose">Operation purpose the proof must have been minted for, or <see langword="null" /> to allow a general freshness proof.</param>
    /// <returns>A failure code when the proof is missing, mismatched, or expired; otherwise <see langword="null" />.</returns>
    public static AshlarFailureCode? ValidateMfaProof(
        Guid userId,
        TenantContext tenant,
        FreshMfaVerificationProof? proof,
        Guid? currentSessionId,
        DateTimeOffset now,
        string? requiredPurpose = null)
    {
        if (proof == null)
        {
            return AshlarFailureCodes.StepUpRequired;
        }

        return Validate(userId, tenant, new FreshVerificationProofData(proof.UserId, proof.TenantId, proof.SessionId, proof.ExpiresAt, proof.Purpose), currentSessionId, now, requiredPurpose);
    }

    /// <summary>
    /// Validates a fresh primary-authentication proof for a first-factor self-service operation.
    /// </summary>
    /// <param name="userId">The target user that must own the proof.</param>
    /// <param name="tenant">The target tenant scope that must match the proof.</param>
    /// <param name="proof">The proof returned by <see cref="StepUpAuthenticationService.CreateFreshPrimaryAuthenticationProof" />.</param>
    /// <param name="currentSessionId">The current Ashlar session id from the authenticated request.</param>
    /// <param name="now">Current UTC time.</param>
    /// <param name="requiredPurpose">Operation purpose the proof must have been minted for, or <see langword="null" /> to allow a general freshness proof.</param>
    /// <returns>A failure code when the proof is missing, mismatched, or expired; otherwise <see langword="null" />.</returns>
    public static AshlarFailureCode? ValidatePrimaryAuthenticationProof(
        Guid userId,
        TenantContext tenant,
        FreshPrimaryAuthenticationProof? proof,
        Guid? currentSessionId,
        DateTimeOffset now,
        string? requiredPurpose = null)
    {
        if (proof == null)
        {
            return AshlarFailureCodes.StepUpRequired;
        }

        return Validate(userId, tenant, new FreshVerificationProofData(proof.UserId, proof.TenantId, proof.SessionId, proof.ExpiresAt, proof.Purpose), currentSessionId, now, requiredPurpose);
    }

    private static AshlarFailureCode? Validate(
        Guid userId,
        TenantContext tenant,
        FreshVerificationProofData proof,
        Guid? currentSessionId,
        DateTimeOffset now,
        string? requiredPurpose)
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

        if (requiredPurpose != null && !string.Equals(proof.Purpose, requiredPurpose, StringComparison.Ordinal))
        {
            return AshlarFailureCodes.StepUpRequired;
        }

        return proof.ExpiresAt <= now ? AshlarFailureCodes.StepUpExpired : null;
    }

    private readonly record struct FreshVerificationProofData(Guid UserId, Guid? TenantId, Guid SessionId, DateTimeOffset ExpiresAt, string? Purpose);
}
