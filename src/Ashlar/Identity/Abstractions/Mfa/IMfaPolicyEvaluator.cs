namespace Ashlar.Identity.Abstractions.Mfa;

/// <summary>
/// Evaluates whether a user must complete MFA before a session is issued.
/// </summary>
public interface IMfaPolicyEvaluator
{
    /// <summary>
    /// Determines the MFA requirement for the current authentication context.
    /// </summary>
    /// <param name="user">User account being authenticated.</param>
    /// <param name="context">Request metadata supplied by the host application.</param>
    /// <param name="cancellationToken">A token that can cancel policy evaluation.</param>
    /// <returns>The MFA requirement that the host application must orchestrate before issuing a session.</returns>
    Task<MfaPolicyEvaluation> EvaluateAsync(IUser user, AuthenticationContext context, CancellationToken cancellationToken = default);
}
