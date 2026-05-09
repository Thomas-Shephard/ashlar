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

    public AuthenticationProviderKey Key => _options.ProviderKey;

    public bool ProtectsCredentials => false;

    public int TypicalCredentialLength => 128; // Hashed password length

    public string GetProviderKey(IAuthenticationAssertion assertion, Guid userId) => string.Empty;

    public string? PrepareCredentialValue(IAuthenticationAssertion assertion, string? rawValue)
    {
        if (string.IsNullOrWhiteSpace(rawValue))
        {
            return null;
        }

        var hashed = PasswordCredentialHashing.HashToBase64(_hasherSelector, rawValue);
        return hashed;
    }

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
