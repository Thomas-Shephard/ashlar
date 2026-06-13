using Microsoft.Extensions.Options;

namespace Ashlar.Identity.Features.Mfa;

/// <summary>
/// Requires configured MFA factors for every user that can sign in.
/// </summary>
public sealed class RequireMfaForAllUsersPolicyEvaluator : IMfaPolicyEvaluator
{
    private readonly RequireMfaForAllUsersPolicyOptions _options;

    /// <summary>
    /// Initializes the policy evaluator from configured MFA requirements.
    /// </summary>
    /// <param name="options">Configured MFA requirements.</param>
    /// <exception cref="OptionsValidationException">Thrown when the configured MFA policy options are invalid.</exception>
    public RequireMfaForAllUsersPolicyEvaluator(IOptions<RequireMfaForAllUsersPolicyOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options.Value;
        if (!RequireMfaForAllUsersPolicyOptions.Validate(_options))
        {
            throw new OptionsValidationException(
                Options.DefaultName,
                typeof(RequireMfaForAllUsersPolicyOptions),
                ["At least one non-empty required factor must be configured."]);
        }
    }

    /// <summary>
    /// Evaluates whether the user must complete the configured factors.
    /// </summary>
    /// <param name="user">User being authenticated.</param>
    /// <param name="context">Authentication request context supplied by the host application.</param>
    /// <param name="cancellationToken">A token that can cancel policy evaluation.</param>
    /// <returns>The MFA requirement for the user.</returns>
    public Task<MfaPolicyEvaluation> EvaluateAsync(IUser user, AuthenticationContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(context);

        if (!user.CanSignIn())
        {
            return Task.FromResult(new MfaPolicyEvaluation(false));
        }

        return Task.FromResult(new MfaPolicyEvaluation(true, new MfaRequirement(_options.RequiredFactors)));
    }
}
