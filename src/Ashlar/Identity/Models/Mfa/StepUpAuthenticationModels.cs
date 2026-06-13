namespace Ashlar.Identity.Models.Mfa;

/// <summary>
/// Describes the additional verification freshness required for a sensitive action.
/// </summary>
/// <param name="FreshnessWindow">Maximum age of an additional-verification ceremony that may satisfy step-up.</param>
/// <param name="AllowedProviders">Provider keys that may satisfy the step-up requirement, or <see langword="null" /> to allow any.</param>
/// <param name="AllowedFactors">Provider-neutral factor families that may satisfy the step-up requirement, or <see langword="null" /> to allow any.</param>
public sealed record StepUpRequirement(
    TimeSpan FreshnessWindow,
    IReadOnlyCollection<AuthenticationProviderKey>? AllowedProviders = null,
    IReadOnlyCollection<string>? AllowedFactors = null);

/// <summary>
/// Describes a step-up evaluation request.
/// </summary>
/// <param name="Session">Application session whose additional-verification metadata is evaluated.</param>
/// <param name="Requirement">Freshness and provider restrictions for the sensitive action.</param>
public sealed record StepUpEvaluationRequest(AuthenticationSession? Session, StepUpRequirement Requirement);

/// <summary>
/// Describes the result of a step-up freshness evaluation.
/// </summary>
/// <param name="Succeeded">Whether the requirement was satisfied.</param>
/// <param name="FailureCode">Stable failure identifier when evaluation failed.</param>
/// <param name="FailureReason">Display-safe explanation when evaluation failed.</param>
public sealed record StepUpEvaluationResult(bool Succeeded, AshlarFailureCode? FailureCode = null, string? FailureReason = null)
{
    /// <summary>
    /// Gets a successful evaluation result.
    /// </summary>
    public static StepUpEvaluationResult Success { get; } = new(true);
}
