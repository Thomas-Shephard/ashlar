using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity;

public sealed class RequireMfaForAllUsersPolicyEvaluator : IMfaPolicyEvaluator
{
    private readonly RequireMfaForAllUsersPolicyOptions _options;

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

    public Task<MfaPolicyEvaluation> EvaluateAsync(IUser user, AuthenticationContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(context);

        if (!user.IsActive)
        {
            return Task.FromResult(new MfaPolicyEvaluation(false));
        }

        return Task.FromResult(new MfaPolicyEvaluation(true, new MfaRequirement(_options.RequiredFactors)));
    }
}
