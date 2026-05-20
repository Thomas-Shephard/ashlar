
namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Evaluates whether a session satisfies a recent additional verification requirement.
/// </summary>
public interface IStepUpAuthenticationService
{
    /// <summary>
    /// Evaluates the supplied session against a step-up requirement.
    /// </summary>
    /// <param name="request">The evaluation request.</param>
    /// <returns>The evaluation result.</returns>
    StepUpEvaluationResult Evaluate(StepUpEvaluationRequest request);

    /// <summary>
    /// Marks an active session as recently verified after a caller has successfully verified an allowed factor.
    /// </summary>
    /// <param name="userId">The session owner user id.</param>
    /// <param name="request">The request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The updated session result.</returns>
    Task<Result<AuthenticationSession>> MarkVerifiedAsync(
        Guid userId,
        MarkSessionStepUpVerifiedRequest request,
        CancellationToken cancellationToken = default);
}
