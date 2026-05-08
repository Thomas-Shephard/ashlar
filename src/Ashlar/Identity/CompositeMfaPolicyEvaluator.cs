using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;

namespace Ashlar.Identity;

public sealed class CompositeMfaPolicyEvaluator : IMfaPolicyEvaluator
{
    private readonly IReadOnlyList<IMfaPolicyEvaluatorComponent> _evaluators;

    public CompositeMfaPolicyEvaluator(IEnumerable<IMfaPolicyEvaluatorComponent> evaluators)
    {
        ArgumentNullException.ThrowIfNull(evaluators);

        _evaluators = evaluators.ToArray();
    }

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

public interface IMfaPolicyEvaluatorComponent : IMfaPolicyEvaluator;

public sealed class MfaPolicyEvaluatorComponent<T>(T evaluator) : IMfaPolicyEvaluatorComponent
    where T : IMfaPolicyEvaluator
{
    private readonly T _evaluator = evaluator ?? throw new ArgumentNullException(nameof(evaluator));

    public Task<MfaPolicyEvaluation> EvaluateAsync(IUser user, AuthenticationContext context, CancellationToken cancellationToken = default)
    {
        return _evaluator.EvaluateAsync(user, context, cancellationToken);
    }
}
