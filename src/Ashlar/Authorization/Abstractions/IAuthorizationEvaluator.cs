using Ashlar.Authorization.Models;

namespace Ashlar.Authorization.Abstractions;

public interface IAuthorizationEvaluator
{
    Task<AuthorizationEvaluationResult> EvaluateAsync(AuthorizationEvaluationRequest request, CancellationToken cancellationToken = default);
}
