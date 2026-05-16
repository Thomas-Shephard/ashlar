using Ashlar.Authorization.Models;

namespace Ashlar.Authorization.Abstractions;

/// <summary>
/// Defines the contract for iauthorization evaluator operations.
/// </summary>
public interface IAuthorizationEvaluator
{
    /// <summary>
    /// Performs the evaluate <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="request">The request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<AuthorizationEvaluationResult> EvaluateAsync(AuthorizationEvaluationRequest request, CancellationToken cancellationToken = default);
}
