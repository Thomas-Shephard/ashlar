namespace Ashlar.Identity.Models;

/// <summary>
/// Describes the additional verification freshness required for a sensitive action.
/// </summary>
/// <param name="FreshnessWindow">The maximum verification age.</param>
/// <param name="AllowedProviders">The optional allowed additional verification providers.</param>
/// <param name="AllowedFactors">The optional allowed additional verification factors.</param>
public sealed record StepUpRequirement(
    TimeSpan FreshnessWindow,
    IReadOnlyCollection<AuthenticationProviderKey>? AllowedProviders = null,
    IReadOnlyCollection<string>? AllowedFactors = null);

/// <summary>
/// Describes a step-up evaluation request.
/// </summary>
/// <param name="Session">The session to evaluate.</param>
/// <param name="Requirement">The freshness requirement.</param>
public sealed record StepUpEvaluationRequest(AuthenticationSession? Session, StepUpRequirement Requirement);

/// <summary>
/// Describes the result of a step-up freshness evaluation.
/// </summary>
/// <param name="Succeeded">Whether the requirement was satisfied.</param>
/// <param name="FailureCode">The stable failure code when evaluation failed.</param>
/// <param name="FailureReason">The display-safe failure reason when evaluation failed.</param>
public sealed record StepUpEvaluationResult(bool Succeeded, AshlarFailureCode? FailureCode = null, string? FailureReason = null)
{
    /// <summary>
    /// Gets a successful evaluation result.
    /// </summary>
    public static StepUpEvaluationResult Success { get; } = new(true);
}
