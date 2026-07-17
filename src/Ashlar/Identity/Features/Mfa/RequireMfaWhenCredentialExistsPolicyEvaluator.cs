using Microsoft.Extensions.Options;

namespace Ashlar.Identity.Features.Mfa;

/// <summary>
/// Requires MFA when the user has an active credential for a configured provider.
/// </summary>
public sealed class RequireMfaWhenCredentialExistsPolicyEvaluator : IMfaPolicyEvaluator
{
    private readonly ICredentialLookup _credentials;
    private readonly CredentialBackedMfaPolicyOptions _options;
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Initializes a configured service instance.
    /// </summary>
    /// <param name="credentials">Read-only credential lookup used to check factor availability.</param>
    /// <param name="options">Configured credential-backed MFA requirements.</param>
    /// <param name="timeProvider">Clock used for credential availability checks.</param>
    /// <exception cref="OptionsValidationException">Thrown when the configured credential-backed MFA policy options are invalid.</exception>
    public RequireMfaWhenCredentialExistsPolicyEvaluator(
        ICredentialLookup credentials,
        IOptions<CredentialBackedMfaPolicyOptions> options,
        TimeProvider? timeProvider = null)
    {
        _credentials = credentials ?? throw new ArgumentNullException(nameof(credentials));
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

    /// <summary>
    /// Evaluates whether matching active credentials require MFA.
    /// </summary>
    /// <param name="user">User being authenticated.</param>
    /// <param name="context">Authentication request context supplied by the host application.</param>
    /// <param name="cancellationToken">A token that can cancel policy evaluation.</param>
    /// <returns>The MFA requirement for the user.</returns>
    public async Task<MfaPolicyEvaluation> EvaluateAsync(IUser user, AuthenticationContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(context);

        if (!user.CanSignIn())
        {
            return new MfaPolicyEvaluation(false);
        }

        var now = _timeProvider.GetUtcNow();
        foreach (var providerKey in _options.CredentialProviderKeys)
        {
            var credential = await _credentials.GetCredentialForUserAsync(user.Id, providerKey.Type, providerKey.Name, cancellationToken: cancellationToken);
            if (credential?.IsAvailable(now) == true)
            {
                return new MfaPolicyEvaluation(true, new MfaRequirement(_options.RequiredFactors));
            }
        }

        return new MfaPolicyEvaluation(false);
    }
}
