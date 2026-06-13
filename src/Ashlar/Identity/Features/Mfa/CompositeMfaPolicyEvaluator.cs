namespace Ashlar.Identity.Features.Mfa;

/// <summary>
/// Combines MFA requirements from registered policy evaluators.
/// </summary>
public sealed class CompositeMfaPolicyEvaluator : IMfaPolicyEvaluator
{
    private readonly IReadOnlyList<IMfaPolicyEvaluatorComponent> _evaluators;

    /// <summary>
    /// Initializes the composite evaluator from registered evaluator components.
    /// </summary>
    /// <param name="evaluators">Policy evaluator components to combine.</param>
    public CompositeMfaPolicyEvaluator(IEnumerable<IMfaPolicyEvaluatorComponent> evaluators)
    {
        ArgumentNullException.ThrowIfNull(evaluators);

        _evaluators = evaluators.ToArray();
    }

    /// <summary>
    /// Evaluates all registered policies and merges required factors.
    /// </summary>
    /// <param name="user">User being authenticated.</param>
    /// <param name="context">Authentication request context supplied by the host application.</param>
    /// <param name="cancellationToken">A token that can cancel policy evaluation.</param>
    /// <returns>The combined MFA requirement for the user.</returns>
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
/// Marker interface for MFA policy evaluators registered as composite components.
/// </summary>
public interface IMfaPolicyEvaluatorComponent : IMfaPolicyEvaluator;

/// <summary>
/// Adapts an MFA policy evaluator into a composite evaluator component.
/// </summary>
/// <typeparam name="T">Policy implementation type.</typeparam>
/// <param name="evaluator">Policy component to invoke.</param>
public sealed class MfaPolicyEvaluatorComponent<T>(T evaluator) : IMfaPolicyEvaluatorComponent
    where T : IMfaPolicyEvaluator
{
    private readonly T _evaluator = evaluator ?? throw new ArgumentNullException(nameof(evaluator));

    /// <summary>
    /// Delegates policy evaluation to the wrapped evaluator.
    /// </summary>
    /// <param name="user">User being authenticated.</param>
    /// <param name="context">Authentication request context supplied by the host application.</param>
    /// <param name="cancellationToken">A token that can cancel policy evaluation.</param>
    /// <returns>The wrapped evaluator's MFA requirement.</returns>
    public Task<MfaPolicyEvaluation> EvaluateAsync(IUser user, AuthenticationContext context, CancellationToken cancellationToken = default)
    {
        return _evaluator.EvaluateAsync(user, context, cancellationToken);
    }
}
