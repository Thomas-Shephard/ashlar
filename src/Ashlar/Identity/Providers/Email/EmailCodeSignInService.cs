using System.Globalization;
using System.Security.Cryptography;
using Ashlar.Auditing;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Messaging;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity.Providers.Email;

public sealed class EmailCodeSignInService : IEmailCodeSignInService
{
    private const string RequestPurpose = "email-code-request";
    private const string VerifyPurpose = "email-code-verify";
    private readonly EmailCodeSignInDependencies _dependencies;
    private readonly IOptions<EmailCodeSignInOptions> _options;
    private readonly SecurityEventEmitter _securityEvents;

    public EmailCodeSignInService(
        EmailCodeSignInDependencies dependencies,
        IOptions<EmailCodeSignInOptions>? options = null)
    {
        _dependencies = dependencies ?? throw new ArgumentNullException(nameof(dependencies));
        _options = options ?? Options.Create(new EmailCodeSignInOptions());
        _securityEvents = new SecurityEventEmitter(_dependencies.SecurityEventSink, _dependencies.TimeProvider);
    }

    public async Task RequestCodeAsync(string email, AuthenticationContext? context = null, CancellationToken cancellationToken = default)
    {
        var normalizedEmail = NormalizeEmail(email);
        context = WithEmail(context, normalizedEmail);

        var signInOptions = _options.Value;
        var rateLimit = await CheckRateLimitAsync(normalizedEmail, RequestPurpose, context, signInOptions.RequestRateLimit, cancellationToken);
        if (!rateLimit.IsAllowed)
        {
            await RecordAsync(AshlarSecurityEventTypes.EmailCodeRequestRateLimited, SecurityEventOutcomes.Failure, context, null, "rate_limited", cancellationToken);
            return;
        }

        await using var transaction = await _dependencies.TransactionProvider.BeginTransactionAsync(cancellationToken);

        var user = await _dependencies.Repository.GetUserByEmailAsync(normalizedEmail, context.TenantId, cancellationToken);
        if (user is not { IsActive: true })
        {
            await RecordAsync(AshlarSecurityEventTypes.EmailCodeRequestSuppressed, SecurityEventOutcomes.Success, context, user?.Id, user == null ? "user_missing" : "user_disabled", cancellationToken);
            
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

        await _dependencies.Repository.CreateOrReplaceCredentialAsync(credential, cancellationToken);
        await _dependencies.EmailSender.SendAsync(new EmailMessage(normalizedEmail, signInOptions.EmailSubject, string.Format(CultureInfo.InvariantCulture, signInOptions.EmailTextTemplate, code, Math.Ceiling(signInOptions.CodeLifetime.TotalMinutes))), cancellationToken);
        await RecordAsync(AshlarSecurityEventTypes.EmailCodeRequested, SecurityEventOutcomes.Success, context, user.Id, null, cancellationToken);

        await transaction.CommitAsync(cancellationToken);
    }

    public async Task<AuthenticationResponse> VerifyCodeAsync(string email, string code, AuthenticationContext? context = null, CancellationToken cancellationToken = default)
    {
        var normalizedEmail = NormalizeEmail(email);
        ArgumentException.ThrowIfNullOrWhiteSpace(code);
        context = WithEmail(context, normalizedEmail);

        var rateLimit = await CheckRateLimitAsync(normalizedEmail, VerifyPurpose, context, _options.Value.VerificationRateLimit, cancellationToken);
        if (!rateLimit.IsAllowed)
        {
            await RecordAsync(AshlarSecurityEventTypes.EmailCodeVerificationRateLimited, SecurityEventOutcomes.Failure, context, null, "rate_limited", cancellationToken);
            return new AuthenticationResponse(false, Status: AuthenticationStatus.Failed);
        }

        return await _dependencies.IdentityService.LoginAsync(context, new EmailCodeAssertion(code), cancellationToken);
    }

    private Task<RateLimitDecision> CheckRateLimitAsync(string email, string purpose, AuthenticationContext context, RateLimitRule rule, CancellationToken cancellationToken)
    {
        return _dependencies.RateLimiter.CheckAsync(new RateLimitAttempt
        {
            Key = $"{purpose}:{email}",
            Purpose = purpose,
            Email = email,
            IpAddress = context.IpAddress,
            CorrelationId = context.CorrelationId
        }, rule, cancellationToken);
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

    private static string NormalizeEmail(string email)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);
        return email.Trim().ToUpperInvariant();
    }

    private static string GenerateCode(int length)
    {
        if (length is <= 0 or > 9)
        {
            throw new ArgumentOutOfRangeException(nameof(length), "Email code length must be between 1 and 9.");
        }

        var max = 1;
        for (var i = 0; i < length; i++)
        {
            max *= 10;
        }

        return RandomNumberGenerator.GetInt32(0, max).ToString(new string('0', length), CultureInfo.InvariantCulture);
    }
}
