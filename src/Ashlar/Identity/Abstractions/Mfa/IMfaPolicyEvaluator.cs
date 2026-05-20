
namespace Ashlar.Identity.Abstractions.Mfa;

/// <summary>
/// Defines the contract for imfa policy evaluator operations.
/// </summary>
public interface IMfaPolicyEvaluator
{
    /// <summary>
    /// Performs the evaluate <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="user">The user value.</param>
    /// <param name="context">The context value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<MfaPolicyEvaluation> EvaluateAsync(IUser user, AuthenticationContext context, CancellationToken cancellationToken = default);
}
