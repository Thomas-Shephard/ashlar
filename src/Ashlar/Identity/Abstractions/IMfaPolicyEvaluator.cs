using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

public interface IMfaPolicyEvaluator
{
    Task<MfaPolicyEvaluation> EvaluateAsync(IUser user, AuthenticationContext context, CancellationToken cancellationToken = default);
}
