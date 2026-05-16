namespace Ashlar.Authorization.Models;

/// <summary>
/// Represents the authorization evaluation result data model.
/// </summary>
/// <param name="Succeeded">The succeeded value.</param>
/// <param name="MatchingGrant">The matching grant value.</param>
public sealed record AuthorizationEvaluationResult(bool Succeeded, AuthorizationGrant? MatchingGrant)
{
    /// <summary>
    /// Executes the new operation.
    /// </summary>
    public static AuthorizationEvaluationResult Failed { get; } = new(false, null);
}
