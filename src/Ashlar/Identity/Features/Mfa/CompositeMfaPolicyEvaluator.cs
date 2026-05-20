
namespace Ashlar.Identity.Features.Mfa;

/// <summary>
/// Provides composite mfa policy evaluator behavior.
/// </summary>
public sealed class CompositeMfaPolicyEvaluator : IMfaPolicyEvaluator
{
    private readonly IReadOnlyList<IMfaPolicyEvaluatorComponent> _evaluators;

    /// <summary>
    /// Initializes a new instance of the composite mfa policy evaluator class.
    /// </summary>
    /// <param name="evaluators">The evaluators value.</param>
    public CompositeMfaPolicyEvaluator(IEnumerable<IMfaPolicyEvaluatorComponent> evaluators)
    {
        ArgumentNullException.ThrowIfNull(evaluators);

        _evaluators = evaluators.ToArray();
    }

    /// <summary>
    /// Performs the evaluate <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="user">The user value.</param>
    /// <param name="context">The context value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<MfaPolicyEvaluation> EvaluateAsync(IUser user, AuthenticationContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(context);

        var requiredFactors = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var isRequired = false;

        foreach (var evaluator in _evaluators)
        {
            var evaluation = await evaluator.EvaluateAsync(user, context, cancellationToken);
            if (!evaluation.IsMfaRequired)
            {
                continue;
            }

            isRequired = true;
            requiredFactors.UnionWith(evaluation.Requirement?.RequiredFactors
                .Where(factor => !string.IsNullOrWhiteSpace(factor))
                .Select(factor => factor.Trim()) ?? []);
        }

        return isRequired
            ? new MfaPolicyEvaluation(true, new MfaRequirement(requiredFactors))
            : new MfaPolicyEvaluation(false);
    }
}

/// <summary>
/// Defines the contract for imfa policy evaluator component operations.
/// </summary>
public interface IMfaPolicyEvaluatorComponent : IMfaPolicyEvaluator;

/// <summary>
/// Provides mfa policy evaluator component behavior.
/// </summary>
/// <typeparam name="T">The result value type.</typeparam>
/// <param name="evaluator">The evaluator value.</param>
public sealed class MfaPolicyEvaluatorComponent<T>(T evaluator) : IMfaPolicyEvaluatorComponent
    where T : IMfaPolicyEvaluator
{
    private readonly T _evaluator = evaluator ?? throw new ArgumentNullException(nameof(evaluator));

    /// <summary>
    /// Performs the evaluate <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="user">The user value.</param>
    /// <param name="context">The context value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public Task<MfaPolicyEvaluation> EvaluateAsync(IUser user, AuthenticationContext context, CancellationToken cancellationToken = default)
    {
        return _evaluator.EvaluateAsync(user, context, cancellationToken);
    }
}



