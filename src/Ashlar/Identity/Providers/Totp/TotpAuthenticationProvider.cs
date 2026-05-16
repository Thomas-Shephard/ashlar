using System.Text.Json;
using Ashlar.Auditing;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.Models.Totp;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Security;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity.Providers.Totp;

/// <summary>
/// Implements an authentication provider that uses TOTP (Time-based One-Time Password) codes.
/// </summary>
public sealed class TotpAuthenticationProvider : IAuthenticationProvider
{
    private readonly IAuthenticationRateLimiter _rateLimiter;
    private readonly TotpOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly SecurityEventEmitter _securityEvents;

    /// <summary>
    /// Initializes a configured service instance.
    /// </summary>
    /// <param name="rateLimiter">The rate limiter value.</param>
    /// <param name="options">The options value.</param>
    /// <param name="timeProvider">The time provider value.</param>
    /// <param name="securityEventSink">The security event sink value.</param>
    public TotpAuthenticationProvider(
        IAuthenticationRateLimiter rateLimiter,
        IOptions<TotpOptions> options,
        TimeProvider? timeProvider = null,
        ISecurityEventSink? securityEventSink = null)
    {
        _rateLimiter = rateLimiter ?? throw new ArgumentNullException(nameof(rateLimiter));
        ArgumentNullException.ThrowIfNull(options);
        _options = options.Value;
        TotpOptions.ThrowIfInvalid(_options);
        _timeProvider = timeProvider ?? TimeProvider.System;
        _securityEvents = new SecurityEventEmitter(securityEventSink, _timeProvider);
    }

    /// <inheritdoc />
    public AuthenticationProviderKey Key => _options.ProviderKey;

    /// <inheritdoc />
    public bool ProtectsCredentials => true;

    /// <inheritdoc />
    public int TypicalCredentialLength => 32;

    /// <inheritdoc />
    public string GetProviderKey(IAuthenticationAssertion assertion, Guid userId) => userId.ToString("D");

    /// <inheritdoc />
    public string? PrepareCredentialValue(IAuthenticationAssertion assertion, string? rawValue) => rawValue;

    /// <inheritdoc />
    public Task<IUser?> FindUserAsync(IAuthenticationAssertion assertion, AuthenticationContext context, IIdentityRepository repository, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(repository);

        if (assertion is not TotpAssertion)
        {
            return Task.FromResult<IUser?>(null);
        }

        if (context.UserId.HasValue)
        {
            return repository.GetUserByIdAsync(context.UserId.Value, cancellationToken);
        }

        return Task.FromResult<IUser?>(null);
    }

    /// <inheritdoc />
    public async Task<UserCredential?> ResolveCredentialAsync(Guid userId, IAuthenticationAssertion assertion, IIdentityRepository repository, CancellationToken cancellationToken = default)
    {
        if (assertion is not TotpAssertion totpAssertion)
        {
            return null;
        }

        var rateLimitKey = userId.ToString("D");
        var rule = new RateLimitRule { PermitLimit = _options.RateLimitPermitLimit, Window = _options.RateLimitWindow };
        var attempt = new RateLimitAttempt { Key = rateLimitKey, Purpose = "totp-verify", IpAddress = totpAssertion.IpAddress };

        var decision = await _rateLimiter.CheckAsync(attempt, rule, cancellationToken);
        if (decision.Status == RateLimitStatus.Blocked)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.TotpVerificationRateLimited,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                Provider = Key,
                FailureReason = AshlarFailureCodes.RateLimited.Value
            }, cancellationToken);
            return null;
        }

        return await repository.GetCredentialForUserAsync(userId, Key.Type, Key.Name, GetProviderKey(assertion, userId), cancellationToken);
    }

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
                if (metadata != null && metadata.LastUsedStep >= verifiedStep)
                {
                    return Task.FromResult(new AuthenticationResult(AuthenticationResultStatus.Failed));
                }
            }
            catch (JsonException)
            {
                // If metadata is malformed, we allow the login but it will be overwritten.
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
        /// Gets or sets the last used step value.
        /// </summary>
        public long LastUsedStep { get; init; }
    }
}
