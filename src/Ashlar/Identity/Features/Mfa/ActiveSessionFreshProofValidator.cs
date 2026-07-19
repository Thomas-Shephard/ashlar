namespace Ashlar.Identity.Features.Mfa;

internal sealed class ActiveSessionFreshProofValidator
{
    private readonly IAuthenticationSessionRepository _sessions;
    private readonly TimeProvider _timeProvider;

    public ActiveSessionFreshProofValidator(IAuthenticationSessionRepository sessions, TimeProvider timeProvider)
    {
        _sessions = sessions ?? throw new ArgumentNullException(nameof(sessions));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    public ValueTask<AshlarFailureCode?> ValidateAsync(Guid userId, TenantContext tenant,
        FreshMfaVerificationProof? proof, Guid? currentSessionId, string purpose, CancellationToken cancellationToken) =>
        ValidateAsync(userId, tenant, proof is null ? null : new ProofData(
            proof.UserId, proof.TenantId, proof.SessionId, proof.ExpiresAt, proof.Purpose), currentSessionId, purpose, cancellationToken);

    public ValueTask<AshlarFailureCode?> ValidateAsync(Guid userId, TenantContext tenant,
        FreshPrimaryAuthenticationProof? proof, Guid? currentSessionId, string purpose, CancellationToken cancellationToken) =>
        ValidateAsync(userId, tenant, proof is null ? null : new ProofData(
            proof.UserId, proof.TenantId, proof.SessionId, proof.ExpiresAt, proof.Purpose), currentSessionId, purpose, cancellationToken);

    private async ValueTask<AshlarFailureCode?> ValidateAsync(Guid userId, TenantContext tenant,
        ProofData? proof, Guid? currentSessionId, string purpose, CancellationToken cancellationToken)
    {
        if (proof is null) return AshlarFailureCodes.StepUpRequired;
        var proofData = proof.Value;
        var now = _timeProvider.GetUtcNow();
        var failure = Validate(userId, tenant, proofData, currentSessionId, now, purpose);
        if (failure != null) return failure;

        var session = await _sessions.GetSessionAsync(proofData.SessionId, cancellationToken);
        now = _timeProvider.GetUtcNow();
        return Validate(userId, tenant, proofData, currentSessionId, now, purpose)
            ?? ValidateSession(session, proofData.SessionId, userId, tenant, now);
    }

    private static AshlarFailureCode? Validate(Guid userId, TenantContext tenant, ProofData proof,
        Guid? currentSessionId, DateTimeOffset now, string requiredPurpose)
    {
        if (userId == Guid.Empty) return AshlarFailureCodes.StepUpRequired;
        if (proof.UserId != userId || proof.TenantId != tenant.TenantId) return AshlarFailureCodes.TenantMismatch;
        if (currentSessionId is null || proof.SessionId != currentSessionId.Value) return AshlarFailureCodes.StepUpRequired;
        if (!string.Equals(proof.Purpose, requiredPurpose, StringComparison.Ordinal))
            return AshlarFailureCodes.StepUpRequired;
        return proof.ExpiresAt <= now ? AshlarFailureCodes.StepUpExpired : null;
    }

    private static AshlarFailureCode? ValidateSession(AuthenticationSession? session, Guid sessionId, Guid userId, TenantContext tenant, DateTimeOffset now) =>
        session is null || session.Id != sessionId || session.UserId != userId || session.TenantId != tenant.TenantId || !session.IsActive(now)
        ? AshlarFailureCodes.StepUpRequired
        : null;

    private readonly record struct ProofData(Guid UserId, Guid? TenantId, Guid SessionId, DateTimeOffset ExpiresAt, string Purpose);
}
