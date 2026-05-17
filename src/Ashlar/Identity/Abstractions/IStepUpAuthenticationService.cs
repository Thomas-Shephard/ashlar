using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

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
}
