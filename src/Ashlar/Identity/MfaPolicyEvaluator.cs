using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;

namespace Ashlar.Identity;

/// <summary>
/// Provides mfa policy evaluator behavior.
/// </summary>
public sealed class MfaPolicyEvaluator : IMfaPolicyEvaluator
{
    /// <summary>
    /// Performs the evaluate <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="user">The user value.</param>
    /// <param name="context">The context value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public Task<MfaPolicyEvaluation> EvaluateAsync(IUser user, AuthenticationContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(context);

        return Task.FromResult(new MfaPolicyEvaluation(false));
    }
}
