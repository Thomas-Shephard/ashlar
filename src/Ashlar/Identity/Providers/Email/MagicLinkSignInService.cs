using Ashlar.Auditing;
using Ashlar.Identity.RateLimiting;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Messaging;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity.Providers.Email;

/// <summary>
/// Provides magic link sign in service behavior.
/// </summary>
internal sealed class MagicLinkSignInService : IMagicLinkSignInService
{
    private const string RequestPurpose = "magic-link-request";
    private const string VerifyPurpose = "magic-link-verify";
    private readonly MagicLinkSignInDependencies _dependencies;
    private readonly IOptions<MagicLinkSignInOptions> _options;
    private readonly SecurityEventEmitter _securityEvents;
    private readonly AuthenticationRateLimitChecker _rateLimitChecker;

    /// <summary>
    /// Initializes a configured service instance.
    /// </summary>
    /// <param name="dependencies">The dependencies value.</param>
    /// <param name="options">The options value.</param>
    public MagicLinkSignInService(
        MagicLinkSignInDependencies dependencies,
        IOptions<MagicLinkSignInOptions>? options = null)
    {
        _dependencies = dependencies ?? throw new ArgumentNullException(nameof(dependencies));
        _options = options ?? Options.Create(new MagicLinkSignInOptions());
        _securityEvents = new SecurityEventEmitter(_dependencies.SecurityEventSink, _dependencies.TimeProvider);
        _rateLimitChecker = new AuthenticationRateLimitChecker(_dependencies.RateLimiter);
    }

    /// <summary>
    /// Performs the request link <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="email">The email value.</param>
    /// <param name="callbackBaseUri">The callback base uri value.</param>
    /// <param name="context">The context value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task RequestLinkAsync(string email, Uri callbackBaseUri, AuthenticationContext? context = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(callbackBaseUri);

        _dependencies.UriValidator.ValidateOrThrow(callbackBaseUri);

        var normalizedEmail = IdentityNormalization.NormalizeEmail(email);
        context = (context ?? new AuthenticationContext()) with { Email = normalizedEmail };

        var signInOptions = _options.Value;
        var rateLimit = await CheckRateLimitAsync(AuthenticationRateLimitDimensions.Email(normalizedEmail), RequestPurpose, context, signInOptions.RequestRateLimit, cancellationToken);
        if (!rateLimit.IsAllowed)
        {
            await RecordAsync(AshlarSecurityEventTypes.MagicLinkRequestRateLimited, SecurityEventOutcomes.Failure, context, null, "rate_limited", cancellationToken);
            return;
        }

        await using var transaction = await _dependencies.TransactionProvider.BeginTransactionAsync(cancellationToken);

        var user = await _dependencies.UserRepository.GetUserByEmailAsync(normalizedEmail, context.TenantId, cancellationToken);
        if (user == null || !user.CanSignIn())
        {
            transaction.OnCommitted(ct => RecordAsync(AshlarSecurityEventTypes.MagicLinkRequestSuppressed, SecurityEventOutcomes.Success, context, user?.Id, user == null ? "user_missing" : user.AccountState.ToSecurityFailureReason(), ct));

            await transaction.CommitAsync(cancellationToken);
            return;
        }

        var token = _dependencies.TokenGenerator.GenerateToken();
        var tokenHash = _dependencies.TokenHasher.HashToken(token);
        var now = _dependencies.TimeProvider.GetUtcNow();

        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = _dependencies.Provider.Key.Type,
            ProviderName = _dependencies.Provider.Key.Name,
            ProviderKey = tokenHash,
            Version = Guid.NewGuid().ToString("N"),
            CredentialValue = null, // The hash is the ProviderKey
            CreatedAt = now,
            ExpiresAt = now.Add(signInOptions.LinkLifetime),
            Status = CredentialStatus.Active,
            Purpose = MagicLinkAuthenticationProvider.CredentialPurpose
        };

        await _dependencies.CredentialRepository.RevokeCredentialsAsync(user.Id, _dependencies.Provider.Key.Type, _dependencies.Provider.Key.Name, cancellationToken);
        await _dependencies.CredentialRepository.CreateOrReplaceCredentialAsync(credential, cancellationToken);

        var callbackUrl = IdentityUrlHelper.ConstructCallbackUrl(callbackBaseUri, signInOptions.LinkTokenParameterName, token);
        var message = IdentityUrlHelper.FormatEmailBody(signInOptions.EmailTextTemplate, callbackUrl);
        var emailMessage = new EmailMessage(
            normalizedEmail,
            signInOptions.EmailSubject,
            message,
            options: new EmailMessageOptions { Sensitivity = EmailMessageSensitivity.ContainsLiveSecret });
        await TransactionalEmailDelivery.SendOrRegisterPostCommitAsync(_dependencies.EmailSender, transaction, emailMessage, cancellationToken);

        transaction.OnCommitted(async ct =>
        {
            await RecordAsync(AshlarSecurityEventTypes.MagicLinkRequested, SecurityEventOutcomes.Success, context, user.Id, null, ct);
        });

        await transaction.CommitAsync(cancellationToken);
    }

    /// <summary>
    /// Performs the verify link <see langword="async" /> operation through MFA-aware orchestration and returns the result.
    /// </summary>
    /// <param name="token">The token value.</param>
    /// <param name="context">The context value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<MfaAuthenticationResult> VerifyLinkAsync(string token, AuthenticationContext? context = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);

        context ??= new AuthenticationContext();

        var sourceRateLimit = await CheckRateLimitAsync(AuthenticationRateLimitDimensions.Source(context), VerifyPurpose, context, _options.Value.VerificationRateLimit, cancellationToken);
        if (!sourceRateLimit.IsAllowed)
        {
            await RecordAsync(AshlarSecurityEventTypes.MagicLinkVerificationRateLimited, SecurityEventOutcomes.Failure, context, null, "rate_limited", cancellationToken);
            return new MfaAuthenticationResult(MfaAuthenticationStatus.RateLimited, ErrorMessage: "Authentication failed.");
        }

        if (!SecureTokenHashing.TryHashToken(_dependencies.TokenHasher, token, out var tokenHash))
        {
            await RecordAsync(AshlarSecurityEventTypes.AuthenticationFailed, SecurityEventOutcomes.Failure, context, null, "invalid_token", cancellationToken);
            return new MfaAuthenticationResult(MfaAuthenticationStatus.Failed, ErrorMessage: "Authentication failed.");
        }

        var tokenRateLimit = await CheckRateLimitAsync(AuthenticationRateLimitDimensions.TokenHash(tokenHash), VerifyPurpose, context, _options.Value.VerificationRateLimit, cancellationToken);
        if (!tokenRateLimit.IsAllowed)
        {
            await RecordAsync(AshlarSecurityEventTypes.MagicLinkVerificationRateLimited, SecurityEventOutcomes.Failure, context, null, "rate_limited", cancellationToken);
            return new MfaAuthenticationResult(MfaAuthenticationStatus.RateLimited, ErrorMessage: "Authentication failed.");
        }

        return await _dependencies.AuthenticationOrchestrator.AuthenticateAsync(context, new MagicLinkAssertion(token), cancellationToken: cancellationToken);
    }

    private Task<RateLimitDecision> CheckRateLimitAsync(string key, string purpose, AuthenticationContext context, RateLimitRule rule, CancellationToken cancellationToken)
    {
        return _rateLimitChecker.CheckAsync(new AuthenticationRateLimitCheck(purpose, AuthenticationRateLimitDimensions.DimensionName(key), key, rule)
        {
            ProviderKey = _dependencies.Provider.Key,
            Context = context
        }, cancellationToken);
    }

    private Task RecordAsync(string eventType, string outcome, AuthenticationContext context, Guid? userId, string? failureReason, CancellationToken cancellationToken)
    {
        return _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = eventType,
            Outcome = outcome,
            UserId = userId,
            Provider = _dependencies.Provider.Key,
            Context = context,
            FailureReason = failureReason
        }, cancellationToken);
    }
}
