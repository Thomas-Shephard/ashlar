namespace Ashlar.Identity.Features.Mfa;

internal sealed class ActiveSessionFreshProofValidator : IFreshAuthenticationProofValidator
{
    private readonly IAuthenticationSessionRepository _sessions;
    private readonly TimeProvider _timeProvider;

    public ActiveSessionFreshProofValidator(IAuthenticationSessionRepository sessions, TimeProvider timeProvider)
    {
        _sessions = sessions ?? throw new ArgumentNullException(nameof(sessions));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    public ValueTask<AshlarFailureCode?> ValidateAsync(Guid userId, TenantContext tenant,
        FreshMfaVerificationProof? proof, Guid? currentSessionId, string? purpose, CancellationToken cancellationToken) =>
        ValidateMfaAsync(userId, tenant, proof, currentSessionId, purpose, cancellationToken);

    public ValueTask<AshlarFailureCode?> ValidateAsync(Guid userId, TenantContext tenant,
        FreshPrimaryAuthenticationProof? proof, Guid? currentSessionId, string? purpose, CancellationToken cancellationToken) =>
        ValidatePrimaryAsync(userId, tenant, proof, currentSessionId, purpose, cancellationToken);

    private async ValueTask<AshlarFailureCode?> ValidateMfaAsync(Guid userId, TenantContext tenant,
        FreshMfaVerificationProof? proof, Guid? currentSessionId, string? purpose, CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow();
        var failure = FreshVerificationProofValidator.ValidateMfaProof(userId, tenant, proof, currentSessionId, now, purpose);
        if (failure != null) return failure;

        var session = await _sessions.GetSessionAsync(proof!.SessionId, cancellationToken);
        now = _timeProvider.GetUtcNow();
        return FreshVerificationProofValidator.ValidateMfaProof(userId, tenant, proof, currentSessionId, now, purpose)
            ?? ValidateSession(session, proof.SessionId, userId, tenant, now);
    }

    private async ValueTask<AshlarFailureCode?> ValidatePrimaryAsync(Guid userId, TenantContext tenant,
        FreshPrimaryAuthenticationProof? proof, Guid? currentSessionId, string? purpose, CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow();
        var failure = FreshVerificationProofValidator.ValidatePrimaryAuthenticationProof(userId, tenant, proof, currentSessionId, now, purpose);
        if (failure != null) return failure;

        var session = await _sessions.GetSessionAsync(proof!.SessionId, cancellationToken);
        now = _timeProvider.GetUtcNow();
        return FreshVerificationProofValidator.ValidatePrimaryAuthenticationProof(userId, tenant, proof, currentSessionId, now, purpose)
            ?? ValidateSession(session, proof.SessionId, userId, tenant, now);
    }

    private static AshlarFailureCode? ValidateSession(AuthenticationSession? session, Guid sessionId, Guid userId, TenantContext tenant, DateTimeOffset now) =>
        session is null || session.Id != sessionId || session.UserId != userId || session.TenantId != tenant.TenantId || !session.IsActive(now)
        ? AshlarFailureCodes.StepUpRequired
        : null;
}
