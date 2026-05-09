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
    private readonly TimeProvider _timeProvider;
    private readonly SecurityEventEmitter _securityEvents;
    private readonly IOptions<EmailVerificationOptions> _options;
    private readonly SecurityNotificationEmitter _notifications;

    public EmailVerificationService(
        IdentityContext identityContext,
        SecureTokenContext tokenContext,
        IEmailSender emailSender,
        IAuthenticationRateLimiter rateLimiter,
        EmailVerificationServiceDependencies dependencies)
    {
        ArgumentNullException.ThrowIfNull(dependencies);

        _identityContext = identityContext ?? throw new ArgumentNullException(nameof(identityContext));
        _tokenContext = tokenContext ?? throw new ArgumentNullException(nameof(tokenContext));
        _emailSender = emailSender ?? throw new ArgumentNullException(nameof(emailSender));
        _rateLimiter = rateLimiter ?? throw new ArgumentNullException(nameof(rateLimiter));
        _timeProvider = dependencies.TimeProvider;
        _securityEvents = new SecurityEventEmitter(dependencies.SecurityEventSink, dependencies.TimeProvider);
        _options = dependencies.Options ?? Options.Create(new EmailVerificationOptions());
        _notifications = new SecurityNotificationEmitter(dependencies.NotificationService);
    }

    public async Task<EmailVerificationResult> RequestVerificationAsync(EmailVerificationRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

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

        transaction.OnCommitted(async ct =>
        {
            await _emailSender.SendAsync(new EmailMessage(
                user.Email,
                _options.Value.Subject,
                $"Verification token: {token}",
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
            return EmailVerificationResult.Failure("Token already used or expired.");
        }

        var user = await _identityContext.Repository.GetUserByIdAsync(userId, cancellationToken);
        if (user is not { IsActive: true })
        {
            return EmailVerificationResult.Failure("User not found or inactive.");
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
    TimeProvider timeProvider,
    ISecurityEventSink securityEventSink,
    IOptions<EmailVerificationOptions>? options = null,
    ISecurityNotificationService? notificationService = null)
{
    public TimeProvider TimeProvider { get; } = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    public ISecurityEventSink SecurityEventSink { get; } = securityEventSink ?? throw new ArgumentNullException(nameof(securityEventSink));
    public IOptions<EmailVerificationOptions>? Options { get; } = options;
    public ISecurityNotificationService? NotificationService { get; } = notificationService;
}
