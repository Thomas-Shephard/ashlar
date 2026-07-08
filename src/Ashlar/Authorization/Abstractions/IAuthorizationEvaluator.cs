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
    /// <param name="cancellationToken">A token that can cancel authorization evaluation.</param>
    /// <returns>The authorization decision and any matching grant summary.</returns>
    Task<AuthorizationEvaluationResult> EvaluateAsync(AuthorizationEvaluationRequest request, CancellationToken cancellationToken = default);
}
