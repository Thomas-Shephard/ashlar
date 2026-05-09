namespace Ashlar.Authorization.Models;

public sealed record AuthorizationEvaluationResult(bool Succeeded, AuthorizationGrant? MatchingGrant)
{
    public static AuthorizationEvaluationResult Failed { get; } = new(false, null);
}
