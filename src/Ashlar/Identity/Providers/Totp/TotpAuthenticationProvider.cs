using System.Text.Json;
using Ashlar.Identity.Models.Totp;
using Ashlar.Security;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity.Providers.Totp;

/// <summary>
/// Implements an authentication provider that uses TOTP (Time-based One-Time Password) codes.
/// </summary>
public sealed class TotpAuthenticationProvider : ISecondaryAuthenticationFactorProvider
{
    private readonly TotpOptions _options;
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Initializes a configured service instance.
    /// </summary>
    /// <param name="options">TOTP provider configuration.</param>
    /// <param name="timeProvider">Clock used to evaluate time-step windows, or <see langword="null" /> to use the system clock.</param>
    public TotpAuthenticationProvider(
        IOptions<TotpOptions> options,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options.Value;
        TotpOptions.ThrowIfInvalid(_options);
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public AuthenticationProviderKey Key => _options.ProviderKey;

    /// <inheritdoc />
    public bool ProtectsCredentials => true;

    /// <inheritdoc />
    public int TypicalCredentialLength => 32;

    /// <inheritdoc />
    public string FactorType => AuthenticationFactorTypes.Totp;

    /// <inheritdoc />
    public bool CanSatisfyFactor(string factorType) => AuthenticationFactorTypes.Matches(FactorType, factorType);

    /// <inheritdoc />
    public string GetProviderKey(IAuthenticationAssertion assertion, Guid userId) => userId.ToString("D");

    /// <inheritdoc />
    public string? PrepareCredentialValue(IAuthenticationAssertion assertion, string? rawValue) => rawValue;

    /// <inheritdoc />
    public Task<AuthenticationResult> AuthenticateAsync(IAuthenticationAssertion assertion, UserCredential? credential, CancellationToken cancellationToken = default)
    {
        if (assertion is not TotpAssertion totpAssertion)
        {
            throw new ArgumentException($"Unsupported assertion type: {assertion.GetType().Name}", nameof(assertion));
        }

        if (credential?.CredentialValue == null)
        {
            return Task.FromResult(new AuthenticationResult(AuthenticationResultStatus.Failed));
        }

        if (!Base32.TryDecode(credential.CredentialValue, out var secretBytes))
        {
            return Task.FromResult(new AuthenticationResult(AuthenticationResultStatus.Failed));
        }

        var now = _timeProvider.GetUtcNow();
        var normalizedCode = totpAssertion.Code.Trim();

        var (verified, verifiedStep) = TotpAuthenticator.VerifyTotp(secretBytes, normalizedCode, now, _options.StepSeconds, _options.CodeDigits, _options.AllowedSkewSteps);

        if (!verified)
        {
            return Task.FromResult(new AuthenticationResult(AuthenticationResultStatus.Failed));
        }

        // Replay protection: ensure this time-step hasn't been used before.
        if (!string.IsNullOrEmpty(credential.Metadata))
        {
            try
            {
                var metadata = JsonSerializer.Deserialize<TotpMetadata>(credential.Metadata);
                if (metadata?.LastUsedStep is not { } lastUsedStep || lastUsedStep < 0)
                {
                    return Task.FromResult(new AuthenticationResult(AuthenticationResultStatus.Failed));
                }

                if (lastUsedStep >= verifiedStep)
                {
                    return Task.FromResult(new AuthenticationResult(AuthenticationResultStatus.Failed));
                }
            }
            catch (JsonException)
            {
                return Task.FromResult(new AuthenticationResult(AuthenticationResultStatus.Failed));
            }
        }

        var newMetadata = JsonSerializer.Serialize(new TotpMetadata { LastUsedStep = verifiedStep });
        return Task.FromResult(new AuthenticationResult(
            AuthenticationResultStatus.SucceededWithCredentialUpdate,
            NewMetadata: newMetadata,
            CredentialUpdateRequirement: CredentialUpdateRequirement.Required));

    }

    private sealed class TotpMetadata
    {
        /// <summary>
        /// Gets the last accepted TOTP time step used for replay protection.
        /// </summary>
        public long? LastUsedStep { get; init; }
    }
}
