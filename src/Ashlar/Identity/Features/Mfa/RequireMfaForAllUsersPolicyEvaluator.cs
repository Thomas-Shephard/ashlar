using Microsoft.Extensions.Options;

namespace Ashlar.Identity.Features.Mfa;

/// <summary>
/// Provides require mfa for all users policy evaluator behavior.
/// </summary>
public sealed class RequireMfaForAllUsersPolicyEvaluator : IMfaPolicyEvaluator
{
    private readonly RequireMfaForAllUsersPolicyOptions _options;

    /// <summary>
    /// Initializes a new instance of the require mfa for all users policy evaluator class.
    /// </summary>
    /// <param name="options">The options value.</param>
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
    /// Performs the evaluate <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="user">The user value.</param>
    /// <param name="context">The context value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
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
