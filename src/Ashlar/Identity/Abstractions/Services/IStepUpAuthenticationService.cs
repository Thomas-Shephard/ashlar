namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Evaluates whether a session satisfies a recent additional verification requirement.
/// </summary>
public interface IStepUpAuthenticationService
{
    /// <summary>
    /// Evaluates the supplied session against a step-up requirement.
    /// </summary>
    /// <param name="request">Session metadata and freshness requirement to evaluate.</param>
    /// <returns>Decision describing whether the session satisfies the requested step-up requirement.</returns>
    StepUpEvaluationResult Evaluate(StepUpEvaluationRequest request);

    /// <summary>
    /// Creates a non-forgeable proof for sensitive self-service MFA management after the supplied session satisfies a step-up requirement.
    /// </summary>
    /// <param name="request">Session metadata and freshness requirement to evaluate.</param>
    /// <returns>Fresh-verification proof scoped to the same user, tenant, and session, or a failure when step-up is missing or stale.</returns>
    /// <remarks>
    /// Hosts should pass the current Ashlar-validated session. Client-supplied JSON, claims, remembered-device tokens, and raw booleans
    /// are not proof for TOTP or recovery-code management.
    /// </remarks>
    Result<FreshMfaVerificationProof> CreateFreshMfaProof(StepUpEvaluationRequest request);

    /// <summary>
    /// Creates a non-forgeable proof for first additional-verification factor bootstrap after the supplied session satisfies a recent primary-authentication requirement.
    /// </summary>
    /// <param name="request">Session metadata and freshness window to evaluate.</param>
    /// <returns>Fresh primary-authentication proof scoped to the same user, tenant, and session, or a failure when sign-in is missing or stale.</returns>
    /// <remarks>
    /// Use this only for operations that cannot require existing MFA, such as TOTP enrollment when the account has no usable
    /// MFA factor. Existing MFA replacement, disable, and recovery-code management must require <see cref="FreshMfaVerificationProof" /> instead.
    /// </remarks>
    Result<FreshPrimaryAuthenticationProof> CreateFreshPrimaryAuthenticationProof(PrimaryAuthenticationEvaluationRequest request);

    /// <summary>
    /// Marks an active session as recently verified after a caller has successfully verified an allowed factor.
    /// </summary>
    /// <param name="userId">Session owner user identifier.</param>
    /// <param name="request">Session and factor metadata to mark as freshly verified.</param>
    /// <param name="cancellationToken">A token that can cancel the update.</param>
    /// <returns>Updated session with step-up verification metadata, or a failure status.</returns>
    Task<Result<AuthenticationSession>> MarkVerifiedAsync(
        Guid userId,
        MarkSessionStepUpVerifiedRequest request,
        CancellationToken cancellationToken = default);
}
