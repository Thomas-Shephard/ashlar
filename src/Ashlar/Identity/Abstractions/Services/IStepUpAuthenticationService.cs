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
