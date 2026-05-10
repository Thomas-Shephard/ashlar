using Ashlar.Auditing;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Messaging;
using Ashlar.Security.Tokens;
using Ashlar.Identity.Notifications;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity;

public sealed class EmailVerificationService : IEmailVerificationService
{
    private const string RequestPurpose = "email-verification-request";
    private const string VerifyPurpose = "email-verification-verify";
    private const string CredentialPurpose = "email-verification";
    private const string ProviderName = "email-verification";
    private readonly IdentityContext _identityContext;
    private readonly SecureTokenContext _tokenContext;
    private readonly IEmailSender _emailSender;
    private readonly IAuthenticationRateLimiter _rateLimiter;
    private readonly IUriValidator _uriValidator;
    private readonly TimeProvider _timeProvider;
    private readonly SecurityEventEmitter _securityEvents;
    private readonly IOptions<EmailVerificationOptions> _options;
    private readonly SecurityNotificationEmitter _notifications;

    public EmailVerificationService(EmailVerificationServiceDependencies dependencies)
    {
        ArgumentNullException.ThrowIfNull(dependencies);

        _identityContext = dependencies.IdentityContext;
        _tokenContext = dependencies.TokenContext;
        _emailSender = dependencies.EmailSender;
        _rateLimiter = dependencies.RateLimiter;
        _uriValidator = dependencies.UriValidator;
        _timeProvider = dependencies.TimeProvider;
        _securityEvents = new SecurityEventEmitter(dependencies.SecurityEventSink, dependencies.TimeProvider);
        _options = dependencies.Options ?? Options.Create(new EmailVerificationOptions());
        _notifications = new SecurityNotificationEmitter(dependencies.NotificationService);
    }

    public async Task<EmailVerificationResult> RequestVerificationAsync(EmailVerificationRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!_uriValidator.IsValid(request.CallbackBaseUri))
        {
            return EmailVerificationResult.Failure($"The URI '{request.CallbackBaseUri}' is not allowed.");
        }

        var user = await _identityContext.Repository.GetUserByIdAsync(request.UserId, cancellationToken);
        if (user is not { IsActive: true })
        {
            return EmailVerificationResult.Failure("User not found or inactive.");
        }

        if (user.EmailVerifiedAt.HasValue)
        {
            return EmailVerificationResult.Success();
        }

        var rateLimit = await _rateLimiter.CheckAsync(new RateLimitAttempt
        {
            Key = $"{RequestPurpose}:{user.Id}",
            Purpose = RequestPurpose,
            Email = user.Email,
            UserId = user.Id.ToString()
        }, new RateLimitRule { PermitLimit = 3, Window = TimeSpan.FromHours(1) }, cancellationToken);

        if (!rateLimit.IsAllowed)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailVerificationRateLimited,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = user.Id,
                FailureReason = "rate_limited"
            }, cancellationToken);
            return EmailVerificationResult.Failure("Too many requests.");
        }

        var token = _tokenContext.Generator.GenerateToken();
        var tokenHash = _tokenContext.Hasher.HashToken(token);
        var now = _timeProvider.GetUtcNow();

        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.Internal,
            ProviderName = ProviderName,
            ProviderKey = tokenHash,
            Version = Guid.NewGuid().ToString("N"),
            CreatedAt = now,
            ExpiresAt = now.Add(_options.Value.Expiration),
            Status = CredentialStatus.Active,
            Purpose = CredentialPurpose
        };

        await using var transaction = await _identityContext.TransactionProvider.BeginTransactionAsync(cancellationToken);

        await _identityContext.Repository.RevokeCredentialsAsync(user.Id, ProviderType.Internal, ProviderName, cancellationToken);
        await _identityContext.Repository.CreateOrReplaceCredentialAsync(credential, cancellationToken);

        var callbackUrl = IdentityUrlHelper.ConstructCallbackUrl(request.CallbackBaseUri, _options.Value.TokenParameterName, token, user.Id, _options.Value.UserIdParameterName);
        var message = IdentityUrlHelper.FormatEmailBody(_options.Value.EmailTextTemplate, callbackUrl, "Verification token", token);

        transaction.OnCommitted(async ct =>
        {
            await _emailSender.SendAsync(new EmailMessage(
                user.Email,
                _options.Value.Subject,
                message,
                options: new EmailMessageOptions { From = _options.Value.FromAddress }), ct);

            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailVerificationRequested,
                Outcome = SecurityEventOutcomes.Success,
                UserId = user.Id
            }, ct);
        });

        await transaction.CommitAsync(cancellationToken);

        return EmailVerificationResult.Success();
    }

    public async Task<EmailVerificationResult> VerifyTokenAsync(Guid userId, string token, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);

        var rateLimit = await _rateLimiter.CheckAsync(new RateLimitAttempt
        {
            Key = $"{VerifyPurpose}:{userId}",
            Purpose = VerifyPurpose,
            UserId = userId.ToString()
        }, new RateLimitRule { PermitLimit = 5, Window = TimeSpan.FromMinutes(15) }, cancellationToken);

        if (!rateLimit.IsAllowed)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailVerificationVerificationRateLimited,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                FailureReason = "rate_limited"
            }, cancellationToken);
            return EmailVerificationResult.Failure("Too many attempts.");
        }

        var tokenHash = _tokenContext.Hasher.HashToken(token);
        var credential = await _identityContext.Repository.GetCredentialForUserAsync(userId, ProviderType.Internal, ProviderName, tokenHash, cancellationToken);

        var now = _timeProvider.GetUtcNow();
        if (credential == null || !credential.IsAvailable(now))
        {
            return EmailVerificationResult.Failure("Invalid or expired token.");
        }

        await using var transaction = await _identityContext.TransactionProvider.BeginTransactionAsync(cancellationToken);

        var consumed = await _identityContext.Repository.ConsumeCredentialAsync(credential.Id, credential.Version, cancellationToken);
        if (!consumed)
        {
            return EmailVerificationResult.Failure("Invalid or expired token.");
        }

        var user = await _identityContext.Repository.GetUserByIdAsync(userId, cancellationToken);
        if (user is not { IsActive: true })
        {
            return EmailVerificationResult.Failure("Invalid or expired token.");
        }

        var updatedUser = new UpdatedUserWrapper(user, now);
        await _identityContext.Repository.UpdateUserAsync(updatedUser, cancellationToken);

        transaction.OnCommitted(async ct =>
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailVerified,
                Outcome = SecurityEventOutcomes.Success,
                UserId = userId
            }, ct);

            await _notifications.NotifyAsync(SecurityNotificationType.EmailVerificationCompleted, updatedUser, now, cancellationToken: ct);
        });

        await transaction.CommitAsync(cancellationToken);

        return EmailVerificationResult.Success();
    }

    private sealed class UpdatedUserWrapper(IUser original, DateTimeOffset? emailVerifiedAt) : ITenantUser, IHasAuditMetadata
    {
        public Guid Id => original.Id;
        public string Email => original.Email;
        public string? Name => original.Name;
        public bool IsActive => original.IsActive;
        public Guid? TenantId => (original as ITenantUser)?.TenantId;
        public DateTimeOffset? EmailVerifiedAt { get; } = emailVerifiedAt;
        public DateTimeOffset CreatedAt => (original as IHasAuditMetadata)?.CreatedAt ?? default;
        public DateTimeOffset? UpdatedAt
        {
            get => (original as IHasAuditMetadata)?.UpdatedAt;
            set
            {
                if (original is IHasAuditMetadata metadata)
                    metadata.UpdatedAt = value;
            }
        }
    }
}

public sealed class EmailVerificationServiceDependencies(
    IdentityContext identityContext,
    SecureTokenContext tokenContext,
    IdentityInfrastructureContext infrastructure,
    IdentityAuditContext audit,
    IOptions<EmailVerificationOptions>? options = null)
{
    public IdentityContext IdentityContext { get; } = identityContext ?? throw new ArgumentNullException(nameof(identityContext));
    public SecureTokenContext TokenContext { get; } = tokenContext ?? throw new ArgumentNullException(nameof(tokenContext));
    public IdentityInfrastructureContext Infrastructure { get; } = infrastructure ?? throw new ArgumentNullException(nameof(infrastructure));
    public IdentityAuditContext Audit { get; } = audit ?? throw new ArgumentNullException(nameof(audit));
    public IOptions<EmailVerificationOptions>? Options { get; } = options;
    public IEmailSender EmailSender => Infrastructure.EmailSender;
    public IAuthenticationRateLimiter RateLimiter => Infrastructure.RateLimiter;
    public IUriValidator UriValidator => Infrastructure.UriValidator;
    public TimeProvider TimeProvider => Audit.TimeProvider;
    public ISecurityEventSink SecurityEventSink => Audit.SecurityEventSink;
    public ISecurityNotificationService? NotificationService => Audit.NotificationService;
}
