using Ashlar.Auditing;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Security.Hashing;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity.Providers.RecoveryCode;

/// <summary>
/// Implements an authentication provider that uses recovery codes.
/// </summary>
public sealed class RecoveryCodeAuthenticationProvider : IAuthenticationProvider
{
    private readonly PasswordHasherSelector _hasherSelector;
    private readonly IAuthenticationRateLimiter _rateLimiter;
    private readonly RecoveryCodeOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly SecurityEventEmitter _securityEvents;

    /// <summary>
    /// Initializes a configured service instance.
    /// </summary>
    /// <param name="hasherSelector">The hasher selector value.</param>
    /// <param name="rateLimiter">The rate limiter value.</param>
    /// <param name="options">The options value.</param>
    /// <param name="timeProvider">The time provider value.</param>
    /// <param name="securityEventSink">The security event sink value.</param>
    public RecoveryCodeAuthenticationProvider(
        PasswordHasherSelector hasherSelector,
        IAuthenticationRateLimiter rateLimiter,
        IOptions<RecoveryCodeOptions> options,
        TimeProvider? timeProvider = null,
        ISecurityEventSink? securityEventSink = null)
    {
        ArgumentNullException.ThrowIfNull(hasherSelector);
        ArgumentNullException.ThrowIfNull(rateLimiter);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(options.Value);

        _hasherSelector = hasherSelector;
        _rateLimiter = rateLimiter;
        _options = options.Value;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _securityEvents = new SecurityEventEmitter(securityEventSink, _timeProvider);
    }

    /// <summary>
    /// Gets or sets the key value.
    /// </summary>
    public AuthenticationProviderKey Key => _options.ProviderKey;

    /// <summary>
    /// Gets or sets the protects credentials value.
    /// </summary>
    public bool ProtectsCredentials => false;

    /// <summary>
    /// Gets or sets the typical credential length value.
    /// </summary>
    public int TypicalCredentialLength => 128; // Hashed password length

    /// <summary>
    /// Executes the get provider key operation.
    /// </summary>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="userId">The user id value.</param>
    /// <returns>The operation result.</returns>
    public string GetProviderKey(IAuthenticationAssertion assertion, Guid userId) => string.Empty;

    /// <summary>
    /// Performs the prepare credential value operation and returns the result.
    /// </summary>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="rawValue">The raw value value.</param>
    /// <returns>The operation result.</returns>
    public string? PrepareCredentialValue(IAuthenticationAssertion assertion, string? rawValue)
    {
        if (string.IsNullOrWhiteSpace(rawValue))
        {
            return null;
        }

        var hashed = PasswordCredentialHashing.HashToBase64(_hasherSelector, rawValue);
        return hashed;
    }

    /// <summary>
    /// Performs the find user <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="context">The context value.</param>
    /// <param name="repository">The repository value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public Task<IUser?> FindUserAsync(IAuthenticationAssertion assertion, AuthenticationContext context, IIdentityRepository repository, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(repository);

        if (assertion is not RecoveryCodeAssertion)
        {
            return Task.FromResult<IUser?>(null);
        }

        if (context.UserId.HasValue)
        {
            return repository.GetUserByIdAsync(context.UserId.Value, cancellationToken);
        }

        var email = context.Email;
        if (string.IsNullOrWhiteSpace(email))
        {
            return Task.FromResult<IUser?>(null);
        }

        return repository.GetUserByEmailAsync(email, context.TenantId, cancellationToken);
    }

    /// <summary>
    /// Performs the resolve credential <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="repository">The repository value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<UserCredential?> ResolveCredentialAsync(Guid userId, IAuthenticationAssertion assertion, IIdentityRepository repository, CancellationToken cancellationToken = default)
    {
        if (assertion is not RecoveryCodeAssertion recoveryCodeAssertion)
        {
            return null;
        }

        var rateLimitKey = userId.ToString("D");
        var rule = new RateLimitRule { PermitLimit = 5, Window = TimeSpan.FromMinutes(5) };
        var attempt = new RateLimitAttempt { Key = rateLimitKey, Purpose = "recovery-code-verify", IpAddress = recoveryCodeAssertion.IpAddress };

        var decision = await _rateLimiter.CheckAsync(attempt, rule, cancellationToken);
        if (decision.Status == RateLimitStatus.Blocked)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.RecoveryCodeVerificationRateLimited,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                Provider = Key,
                FailureReason = "rate_limited"
            }, cancellationToken);
            return null;
        }

        var normalizedCode = recoveryCodeAssertion.Code.Replace(" ", "").ToUpperInvariant();
        var codeSpan = normalizedCode.AsSpan();
        var separatorIndex = codeSpan.IndexOf('-');
        if (separatorIndex <= 0 || separatorIndex == codeSpan.Length - 1)
        {
            // Dummy verification to mitigate timing attacks
            _hasherSelector.VerifyPassword(normalizedCode, []);
            return null;
        }

        var idCode = new string(codeSpan[..separatorIndex]);
        var providerKey = $"{userId:N}-{idCode}";
        var secretCode = new string(codeSpan[(separatorIndex + 1)..]);

        var credential = await repository.GetCredentialForUserAsync(userId, Key.Type, Key.Name, providerKey, cancellationToken);

        if (credential == null || !credential.IsAvailable(_timeProvider.GetUtcNow()))
        {
            // Dummy verification to mitigate timing attacks
            _hasherSelector.VerifyPassword(normalizedCode, []);
            return null;
        }

        var hash = PasswordCredentialHashing.DecodeBase64(credential.CredentialValue);
        var result = _hasherSelector.VerifyPassword(secretCode, hash ?? []);

        if (result is PasswordVerificationResult.Success or PasswordVerificationResult.SuccessWithCredentialUpdate)
        {
            return credential;
        }

        return null;
    }

    /// <summary>
    /// Performs the authenticate <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="credential">The credential value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public Task<AuthenticationResult> AuthenticateAsync(IAuthenticationAssertion assertion, UserCredential? credential, CancellationToken cancellationToken = default)
    {
        if (assertion is not RecoveryCodeAssertion)
        {
            throw new ArgumentException($"Unsupported assertion type: {assertion.GetType().Name}", nameof(assertion));
        }

        if (credential == null)
        {
            return Task.FromResult(new AuthenticationResult(AuthenticationResultStatus.Failed));
        }

        // If we have a credential here, it means ResolveCredentialAsync found a match.
        return Task.FromResult(new AuthenticationResult(AuthenticationResultStatus.Succeeded, IsCredentialConsumed: true));
    }
}
