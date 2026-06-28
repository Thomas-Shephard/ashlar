using System.Globalization;
using System.Security.Cryptography;
using Ashlar.Auditing;
using Ashlar.Identity.RateLimiting;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Messaging;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity.Providers.Email;

/// <summary>
/// Issues and verifies email sign-in codes.
/// </summary>
internal sealed class EmailCodeSignInService : IEmailCodeSignInService
{
    private const string RequestPurpose = "email-code-request";
    private const string VerifyPurpose = "email-code-verify";
    private const string RateLimitedFailureReason = "rate_limited";
    private static readonly int[] PowersOfTen = [1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000];
    private readonly EmailCodeSignInDependencies _dependencies;
    private readonly IOptions<EmailCodeSignInOptions> _options;
    private readonly SecurityEventEmitter _securityEvents;
    private readonly AuthenticationRateLimitChecker _rateLimitChecker;

    /// <summary>
    /// Initializes a configured service instance.
    /// </summary>
    /// <param name="dependencies">Repositories, providers, messaging, audit, and rate limiting services used by email-code sign-in.</param>
    /// <param name="options">Email-code sign-in configuration, or <see langword="null" /> to use defaults.</param>
    public EmailCodeSignInService(
        EmailCodeSignInDependencies dependencies,
        IOptions<EmailCodeSignInOptions>? options = null)
    {
        _dependencies = dependencies ?? throw new ArgumentNullException(nameof(dependencies));
        _options = options ?? Options.Create(new EmailCodeSignInOptions());
        _securityEvents = new SecurityEventEmitter(_dependencies.SecurityEventSink, _dependencies.TimeProvider);
        _rateLimitChecker = new AuthenticationRateLimitChecker(_dependencies.RateLimiter);
    }

    /// <summary>
    /// Creates a transient code credential and sends it to the user when the account can sign in.
    /// </summary>
    /// <param name="email">Email address receiving the sign-in code.</param>
    /// <param name="context">Authentication context used for tenant scope, rate limiting, and audit metadata.</param>
    /// <param name="cancellationToken">Token for aborting repository, messaging, and audit work.</param>
    /// <returns>A task that completes after the request has been handled. Missing or disabled accounts are deliberately suppressed.</returns>
    public async Task RequestCodeAsync(string email, AuthenticationContext? context = null, CancellationToken cancellationToken = default)
    {
        var displayEmail = IdentityNormalization.SanitizeEmailForDelivery(email);
        var normalizedEmail = IdentityNormalization.NormalizeEmail(displayEmail);
        context = WithEmail(context, normalizedEmail);

        var signInOptions = _options.Value;
        var sourceRateLimit = await CheckRateLimitAsync(AuthenticationRateLimitDimensions.Source(context), RequestPurpose, context, signInOptions.RequestRateLimit, cancellationToken);
        if (!sourceRateLimit.IsAllowed)
        {
            await RecordAsync(AshlarSecurityEventTypes.EmailCodeRequestRateLimited, SecurityEventOutcomes.Failure, context, null, RateLimitedFailureReason, cancellationToken);
            return;
        }

        var rateLimit = await CheckRateLimitAsync(AuthenticationRateLimitDimensions.Email(normalizedEmail), RequestPurpose, context, signInOptions.RequestRateLimit, cancellationToken);
        if (!rateLimit.IsAllowed)
        {
            await RecordAsync(AshlarSecurityEventTypes.EmailCodeRequestRateLimited, SecurityEventOutcomes.Failure, context, null, RateLimitedFailureReason, cancellationToken);
            return;
        }

        await using var transaction = await _dependencies.TransactionProvider.BeginTransactionAsync(cancellationToken);

        var user = await _dependencies.UserRepository.GetUserByEmailAsync(displayEmail, context.TenantId, cancellationToken);
        if (user == null || !user.CanSignIn())
        {
            transaction.OnCommitted(ct => RecordAsync(AshlarSecurityEventTypes.EmailCodeRequestSuppressed, SecurityEventOutcomes.Success, context, user?.Id, user == null ? "user_missing" : user.AccountState.ToSecurityFailureReason(), ct));

            await transaction.CommitAsync(cancellationToken);
            return;
        }

        var now = _dependencies.TimeProvider.GetUtcNow();
        var code = GenerateCode(signInOptions.CodeLength);
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = _dependencies.Provider.Key.Type,
            ProviderName = _dependencies.Provider.Key.Name,
            ProviderKey = user.Id.ToString("D"),
            Version = Guid.NewGuid().ToString("N"),
            CredentialValue = _dependencies.Provider.PrepareCredentialValue(new EmailCodeAssertion(code), code),
            CreatedAt = now,
            ExpiresAt = now.Add(signInOptions.CodeLifetime),
            Status = CredentialStatus.Active,
            Purpose = EmailCodeAuthenticationProvider.CredentialPurpose
        };

        await _dependencies.CredentialRepository.CreateOrReplaceCredentialAsync(credential, cancellationToken);

        var lifetimeMinutes = (int)Math.Ceiling(signInOptions.CodeLifetime.TotalMinutes);
        var message = string.Format(CultureInfo.InvariantCulture, signInOptions.EmailTextTemplate, code, lifetimeMinutes);
        var emailMessage = new EmailMessage(
            user.DisplayEmail,
            signInOptions.EmailSubject,
            message,
            options: new EmailMessageOptions { Sensitivity = EmailMessageSensitivity.ContainsLiveSecret });
        await TransactionalEmailDelivery.SendOrRegisterPostCommitAsync(_dependencies.EmailSender, transaction, emailMessage, cancellationToken);

        transaction.OnCommitted(async (ct) =>
        {
            await RecordAsync(AshlarSecurityEventTypes.EmailCodeRequested, SecurityEventOutcomes.Success, context, user.Id, null, ct);
        });

        await transaction.CommitAsync(cancellationToken);
    }

    /// <summary>
    /// Verifies a submitted email code through MFA-aware authentication orchestration.
    /// </summary>
    /// <param name="email">Email address associated with the sign-in request.</param>
    /// <param name="code">User-submitted sign-in code. Do not log this value.</param>
    /// <param name="context">Authentication context used for tenant scope, rate limiting, and audit metadata.</param>
    /// <param name="cancellationToken">Token for aborting verification work.</param>
    /// <returns>MFA-aware result that may succeed, require additional factors, fail, or indicate rate limiting.</returns>
    public Task<MfaAuthenticationResult> VerifyCodeAsync(string email, string code, AuthenticationContext? context = null, CancellationToken cancellationToken = default)
    {
        var normalizedEmail = IdentityNormalization.NormalizeEmail(email);
        ArgumentException.ThrowIfNullOrWhiteSpace(code);
        context = WithEmail(context, normalizedEmail);

        return VerifyCodeCoreAsync(normalizedEmail, code, context, cancellationToken);
    }

    private async Task<MfaAuthenticationResult> VerifyCodeCoreAsync(string normalizedEmail, string code, AuthenticationContext context, CancellationToken cancellationToken)
    {
        var rateLimit = await CheckRateLimitAsync(AuthenticationRateLimitDimensions.Email(normalizedEmail), VerifyPurpose, context, _options.Value.VerificationRateLimit, cancellationToken);
        if (!rateLimit.IsAllowed)
        {
            await RecordAsync(AshlarSecurityEventTypes.EmailCodeVerificationRateLimited, SecurityEventOutcomes.Failure, context, null, RateLimitedFailureReason, cancellationToken);
            return new MfaAuthenticationResult(MfaAuthenticationStatus.RateLimited, ErrorMessage: "Authentication failed.");
        }

        return await _dependencies.AuthenticationOrchestrator.AuthenticateAsync(context, new EmailCodeAssertion(code), cancellationToken: cancellationToken);
    }

    private Task<RateLimitDecision> CheckRateLimitAsync(string key, string purpose, AuthenticationContext context, RateLimitRule rule, CancellationToken cancellationToken)
    {
        return _rateLimitChecker.CheckAsync(new AuthenticationRateLimitCheck(purpose, AuthenticationRateLimitDimensions.DimensionName(key), key, rule)
        {
            ProviderKey = _dependencies.Provider.Key,
            Context = context,
            Email = context.Email
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

    private static AuthenticationContext WithEmail(AuthenticationContext? context, string email)
    {
        return (context ?? new AuthenticationContext()) with { Email = email };
    }

    private static string GenerateCode(int length)
    {
        if (length is < EmailCodeSignInOptions.MinimumCodeLength or > EmailCodeSignInOptions.MaximumCodeLength)
        {
            throw new ArgumentOutOfRangeException(nameof(length), $"Email code length must be between {EmailCodeSignInOptions.MinimumCodeLength} and {EmailCodeSignInOptions.MaximumCodeLength}.");
        }

        var max = PowersOfTen[length];
        return RandomNumberGenerator.GetInt32(0, max).ToString(new string('0', length), CultureInfo.InvariantCulture);
    }
}
