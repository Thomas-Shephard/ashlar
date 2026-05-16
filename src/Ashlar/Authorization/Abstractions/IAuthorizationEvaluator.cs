using Ashlar.Authorization.Models;

namespace Ashlar.Authorization.Abstractions;

/// <summary>
/// Evaluates whether a user has a role or permission grant for a requested scope.
/// </summary>
public interface IAuthorizationEvaluator
{
    /// <summary>
    /// Evaluates one authorization request against stored grants.
    /// </summary>
    /// <param name="request">The authorization request to evaluate.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The authorization decision and any matching grant.</returns>
    Task<AuthorizationEvaluationResult> EvaluateAsync(AuthorizationEvaluationRequest request, CancellationToken cancellationToken = default);
}
