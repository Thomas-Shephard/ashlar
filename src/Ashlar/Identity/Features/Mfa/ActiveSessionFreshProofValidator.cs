namespace Ashlar.Identity.Features.Mfa;

/// <summary>Validates fresh proofs and their source session. Revoking the session invalidates every outstanding proof.</summary>
public sealed class ActiveSessionFreshProofValidator
{
    private readonly IAuthenticationSessionRepository _sessions;
    private readonly TimeProvider _timeProvider;

    /// <summary>Creates a validator backed by the authoritative session repository.</summary>
    /// <param name="sessions">Authoritative session repository.</param>
    /// <param name="timeProvider">Current-time provider.</param>
    public ActiveSessionFreshProofValidator(IAuthenticationSessionRepository sessions, TimeProvider timeProvider)
    {
        _sessions = sessions ?? throw new ArgumentNullException(nameof(sessions));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    /// <summary>Validates an MFA proof and reloads its active source session.</summary>
    /// <param name="userId">Expected session user.</param>
    /// <param name="tenant">Expected session tenant.</param>
    /// <param name="proof">Proof to validate.</param>
    /// <param name="currentSessionId">Authenticated request session.</param>
    /// <param name="purpose">Required proof purpose.</param>
    /// <param name="cancellationToken">Token used to cancel the session lookup.</param>
    /// <returns>A failure code, or <see langword="null" /> when valid.</returns>
    public async ValueTask<AshlarFailureCode?> ValidateAsync(Guid userId, TenantContext tenant,
        FreshMfaVerificationProof? proof, Guid? currentSessionId, string? purpose, CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow();
        var failure = FreshVerificationProofValidator.ValidateMfaProof(userId, tenant, proof, currentSessionId, now, purpose);
        if (failure != null) return failure;

        var session = await _sessions.GetSessionAsync(proof!.SessionId, cancellationToken);
        now = _timeProvider.GetUtcNow();
        return FreshVerificationProofValidator.ValidateMfaProof(userId, tenant, proof, currentSessionId, now, purpose)
            ?? ValidateSession(session, userId, tenant, now);
    }

    /// <summary>Validates a primary-authentication proof and reloads its active source session.</summary>
    /// <param name="userId">Expected session user.</param>
    /// <param name="tenant">Expected session tenant.</param>
    /// <param name="proof">Proof to validate.</param>
    /// <param name="currentSessionId">Authenticated request session.</param>
    /// <param name="purpose">Required proof purpose.</param>
    /// <param name="cancellationToken">Token used to cancel the session lookup.</param>
    /// <returns>A failure code, or <see langword="null" /> when valid.</returns>
    public async ValueTask<AshlarFailureCode?> ValidateAsync(Guid userId, TenantContext tenant,
        FreshPrimaryAuthenticationProof? proof, Guid? currentSessionId, string? purpose, CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow();
        var failure = FreshVerificationProofValidator.ValidatePrimaryAuthenticationProof(userId, tenant, proof, currentSessionId, now, purpose);
        if (failure != null) return failure;

        var session = await _sessions.GetSessionAsync(proof!.SessionId, cancellationToken);
        now = _timeProvider.GetUtcNow();
        return FreshVerificationProofValidator.ValidatePrimaryAuthenticationProof(userId, tenant, proof, currentSessionId, now, purpose)
            ?? ValidateSession(session, userId, tenant, now);
    }

    private static AshlarFailureCode? ValidateSession(AuthenticationSession? session, Guid userId, TenantContext tenant, DateTimeOffset now) =>
        session is null || session.UserId != userId || session.TenantId != tenant.TenantId || !session.IsActive(now)
        ? AshlarFailureCodes.StepUpRequired
        : null;
}
