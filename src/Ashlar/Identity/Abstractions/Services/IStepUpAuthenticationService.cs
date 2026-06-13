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
