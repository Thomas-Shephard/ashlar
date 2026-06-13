namespace Ashlar.Authorization.Models;

/// <summary>
/// Result of evaluating a role or permission grant.
/// </summary>
/// <param name="Succeeded">Whether a currently active grant satisfied the request.</param>
/// <param name="MatchingGrant">The grant that satisfied the request, when one was found.</param>
public sealed record AuthorizationEvaluationResult(bool Succeeded, AuthorizationGrant? MatchingGrant)
{
    /// <summary>
    /// A failed authorization decision with no matching grant.
    /// </summary>
    public static AuthorizationEvaluationResult Failed { get; } = new(false, null);
}
