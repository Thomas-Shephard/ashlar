using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;

namespace Ashlar.Identity;

public sealed class MfaPolicyEvaluator : IMfaPolicyEvaluator
{
    public Task<MfaPolicyEvaluation> EvaluateAsync(IUser user, AuthenticationContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(context);

        return Task.FromResult(new MfaPolicyEvaluation(false));
    }
}
