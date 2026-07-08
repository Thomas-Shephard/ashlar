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
    /// Creates a non-forgeable proof for sensitive self-service operations after the supplied session satisfies a step-up requirement.
    /// </summary>
    /// <param name="request">Session metadata and freshness requirement to evaluate.</param>
    /// <returns>Fresh-verification proof scoped to the same user, tenant, and session, or a failure when step-up is missing or stale.</returns>
    /// <remarks>
    /// Hosts should pass the current Ashlar-validated session. Client-supplied JSON, claims, remembered-device tokens, and raw booleans
    /// are not proof for sensitive operations. Set the requirement purpose when a service requires operation-bound freshness.
    /// </remarks>
    Result<FreshMfaVerificationProof> CreateFreshMfaProof(StepUpEvaluationRequest request);

    /// <summary>
    /// Creates a non-forgeable proof for first additional-verification factor bootstrap after the supplied session satisfies a recent primary-authentication requirement.
    /// </summary>
    /// <param name="request">Session metadata and freshness window to evaluate.</param>
    /// <returns>Fresh primary-authentication proof scoped to the same user, tenant, and session, or a failure when sign-in is missing or stale.</returns>
    /// <remarks>
    /// Use this only for operations that cannot require existing MFA, such as first-factor setup when the account has no
    /// usable MFA factor. Existing MFA replacement, disable, and recovery-code management must require
    /// <see cref="FreshMfaVerificationProof" /> instead. Set the request purpose when a service requires operation-bound freshness.
    /// </remarks>
    Result<FreshPrimaryAuthenticationProof> CreateFreshPrimaryAuthenticationProof(PrimaryAuthenticationEvaluationRequest request);

    /// <summary>
    /// Marks an active session as recently verified after Ashlar has successfully verified an allowed factor.
    /// </summary>
    /// <param name="authenticationResult">Successful Ashlar MFA result carrying the internal step-up marking proof.</param>
    /// <param name="request">Session and factor metadata to mark as freshly verified.</param>
    /// <param name="cancellationToken">A token that can cancel the update.</param>
    /// <returns>Updated session with step-up verification metadata, or a failure status.</returns>
    /// <remarks>Host applications cannot mark step-up by supplying arbitrary user identifiers; the result must come from Ashlar MFA orchestration.</remarks>
    Task<Result<AuthenticationSession>> MarkVerifiedAsync(
        MfaAuthenticationResult authenticationResult,
        MarkSessionStepUpVerifiedRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Marks an active session as recently verified after Ashlar has successfully verified a factor outside the MFA handshake flow.
    /// </summary>
    /// <param name="authenticationResponse">Successful Ashlar factor-pipeline response carrying the internal step-up marking proof.</param>
    /// <param name="request">Session and factor metadata to mark as freshly verified.</param>
    /// <param name="cancellationToken">A token that can cancel the update.</param>
    /// <returns>Updated session with step-up verification metadata, or a failure status.</returns>
    Task<Result<AuthenticationSession>> MarkVerifiedAsync(
        AuthenticationResponse authenticationResponse,
        MarkSessionStepUpVerifiedRequest request,
        CancellationToken cancellationToken = default);
}
