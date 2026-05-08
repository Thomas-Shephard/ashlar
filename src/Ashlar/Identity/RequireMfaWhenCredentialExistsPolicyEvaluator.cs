using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity;

public sealed class RequireMfaWhenCredentialExistsPolicyEvaluator : IMfaPolicyEvaluator
{
    private readonly IIdentityRepository _repository;
    private readonly CredentialBackedMfaPolicyOptions _options;
    private readonly TimeProvider _timeProvider;

    public RequireMfaWhenCredentialExistsPolicyEvaluator(
        IIdentityRepository repository,
        IOptions<CredentialBackedMfaPolicyOptions> options,
        TimeProvider? timeProvider = null)
    {
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
        ArgumentNullException.ThrowIfNull(options);
        _options = options.Value;
        if (!CredentialBackedMfaPolicyOptions.Validate(_options))
        {
            throw new OptionsValidationException(
                Options.DefaultName,
                typeof(CredentialBackedMfaPolicyOptions),
                ["At least one credential provider key and one non-empty required factor must be configured."]);
        }

        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async Task<MfaPolicyEvaluation> EvaluateAsync(IUser user, AuthenticationContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(context);

        if (!user.IsActive)
        {
            return new MfaPolicyEvaluation(false);
        }

        var now = _timeProvider.GetUtcNow();
        foreach (var providerKey in _options.CredentialProviderKeys)
        {
            var credential = await _repository.GetCredentialForUserAsync(user.Id, providerKey.Type, providerKey.Name, cancellationToken: cancellationToken);
            if (credential?.IsAvailable(now) == true)
            {
                return new MfaPolicyEvaluation(true, new MfaRequirement(_options.RequiredFactors));
            }
        }

        return new MfaPolicyEvaluation(false);
    }
}
