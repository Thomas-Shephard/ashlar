using System.Globalization;
using Ashlar.Auditing;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Messaging;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity.Providers.Email;

public sealed class MagicLinkSignInService : IMagicLinkSignInService
{
    private const string RequestPurpose = "magic-link-request";
    private const string VerifyPurpose = "magic-link-verify";
    private readonly MagicLinkSignInDependencies _dependencies;
    private readonly IOptions<MagicLinkSignInOptions> _options;
    private readonly SecurityEventEmitter _securityEvents;

    public MagicLinkSignInService(
        MagicLinkSignInDependencies dependencies,
        IOptions<MagicLinkSignInOptions>? options = null)
    {
        _dependencies = dependencies ?? throw new ArgumentNullException(nameof(dependencies));
        _options = options ?? Options.Create(new MagicLinkSignInOptions());
        _securityEvents = new SecurityEventEmitter(_dependencies.SecurityEventSink, _dependencies.TimeProvider);
    }

    public async Task RequestLinkAsync(string email, Uri callbackBaseUri, AuthenticationContext? context = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(callbackBaseUri);
        var normalizedEmail = NormalizeEmail(email);
        context = WithEmail(context, normalizedEmail);

        var options = _options.Value;
        var rateLimit = await CheckRateLimitAsync(normalizedEmail, RequestPurpose, context, options.RequestRateLimit, cancellationToken);
        if (!rateLimit.IsAllowed)
        {
            await RecordAsync(AshlarSecurityEventTypes.MagicLinkRequestRateLimited, SecurityEventOutcomes.Failure, context, null, "rate_limited", cancellationToken);
            return;
        }

        var user = await _dependencies.Repository.GetUserByEmailAsync(normalizedEmail, context.TenantId, cancellationToken);
        if (user is not { IsActive: true })
        {
            await RecordAsync(AshlarSecurityEventTypes.MagicLinkRequestSuppressed, SecurityEventOutcomes.Success, context, user?.Id, user == null ? "user_missing" : "user_disabled", cancellationToken);
            return;
        }

        var now = _dependencies.TimeProvider.GetUtcNow();
        var token = _dependencies.TokenGenerator.GenerateToken();
        var credentialValue = _dependencies.Provider.PrepareCredentialValue(new MagicLinkAssertion(token), token);

        if (_dependencies.Provider.ProtectsCredentials && credentialValue != null)
        {
            credentialValue = _dependencies.SecretProtector.Protect(credentialValue);
        }

        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = _dependencies.Provider.Key.Type,
            ProviderName = _dependencies.Provider.Key.Name,
            ProviderKey = user.Id.ToString("D"),
            Version = Guid.NewGuid().ToString("N"),
            CredentialValue = credentialValue,
            CreatedAt = now,
            ExpiresAt = now.Add(options.LinkLifetime),
            Status = CredentialStatus.Active,
            Purpose = MagicLinkAuthenticationProvider.CredentialPurpose
        };

        await _dependencies.Repository.CreateOrReplaceCredentialAsync(credential, cancellationToken);

        var link = ConstructLink(callbackBaseUri, normalizedEmail, token, options);

        await _dependencies.EmailSender.SendAsync(new EmailMessage(
            normalizedEmail,
            options.EmailSubject,
            string.Format(CultureInfo.InvariantCulture, options.EmailTextTemplate, link, Math.Ceiling(options.LinkLifetime.TotalMinutes)),
            options.EmailHtmlTemplate != null ? string.Format(CultureInfo.InvariantCulture, options.EmailHtmlTemplate, link, Math.Ceiling(options.LinkLifetime.TotalMinutes)) : null),
            cancellationToken);

        await RecordAsync(AshlarSecurityEventTypes.MagicLinkRequested, SecurityEventOutcomes.Success, context, user.Id, null, cancellationToken);
    }

    public async Task<AuthenticationResponse> VerifyLinkAsync(string email, string token, AuthenticationContext? context = null, CancellationToken cancellationToken = default)
    {
        var normalizedEmail = NormalizeEmail(email);
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        context = WithEmail(context, normalizedEmail);

        var rateLimit = await CheckRateLimitAsync(normalizedEmail, VerifyPurpose, context, _options.Value.VerificationRateLimit, cancellationToken);
        if (!rateLimit.IsAllowed)
        {
            await RecordAsync(AshlarSecurityEventTypes.MagicLinkVerificationRateLimited, SecurityEventOutcomes.Failure, context, null, "rate_limited", cancellationToken);
            return new AuthenticationResponse(false, Status: AuthenticationStatus.Failed);
        }

        return await _dependencies.IdentityService.LoginAsync(context, new MagicLinkAssertion(token), cancellationToken);
    }

    private static string ConstructLink(Uri baseUri, string email, string token, MagicLinkSignInOptions options)
    {
        var uriBuilder = new UriBuilder(baseUri);
        var query = uriBuilder.Query;

        var parameters = new List<string>();
        if (!string.IsNullOrEmpty(query))
        {
            var existingQuery = query.TrimStart('?');
            if (!string.IsNullOrEmpty(existingQuery))
            {
                parameters.AddRange(existingQuery.Split('&', StringSplitOptions.RemoveEmptyEntries));
            }
        }

        var emailParam = options.EmailParameterName;
        var tokenParam = options.LinkTokenParameterName;
        parameters.RemoveAll(p => p.StartsWith(emailParam + "=", StringComparison.OrdinalIgnoreCase) ||
                                 p.StartsWith(tokenParam + "=", StringComparison.OrdinalIgnoreCase));

        parameters.Add($"{Uri.EscapeDataString(emailParam)}={Uri.EscapeDataString(email)}");
        parameters.Add($"{Uri.EscapeDataString(tokenParam)}={Uri.EscapeDataString(token)}");

        uriBuilder.Query = string.Join("&", parameters);
        return uriBuilder.Uri.ToString();
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
}
