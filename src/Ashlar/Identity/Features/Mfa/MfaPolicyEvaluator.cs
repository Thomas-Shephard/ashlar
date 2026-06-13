namespace Ashlar.Identity.Features.Mfa;

/// <summary>
/// Default MFA policy evaluator that does not require secondary verification.
/// </summary>
public sealed class MfaPolicyEvaluator : IMfaPolicyEvaluator
{
    /// <summary>
    /// Evaluates the default MFA policy for a user.
    /// </summary>
    /// <param name="user">User being authenticated.</param>
    /// <param name="context">Authentication request context supplied by the host application.</param>
    /// <param name="cancellationToken">A token that can cancel policy evaluation.</param>
    /// <returns>An evaluation indicating that MFA is not required.</returns>
    public Task<MfaPolicyEvaluation> EvaluateAsync(IUser user, AuthenticationContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(context);

        return Task.FromResult(new MfaPolicyEvaluation(false));
    }
}
