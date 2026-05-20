using Ashlar.Auditing;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Messaging;
using Ashlar.Security.Tokens;
using Ashlar.Identity.Notifications;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity.Features.Email;

/// <summary>
/// Provides email verification service behavior.
/// </summary>
internal sealed class EmailVerificationService : IEmailVerificationService
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

    /// <summary>
    /// Initializes a new instance of the email verification service class.
    /// </summary>
    /// <param name="dependencies">The dependencies value.</param>
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

    /// <summary>
    /// Performs the request verification <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="request">The request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<Result> RequestVerificationAsync(EmailVerificationRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!_uriValidator.IsValid(request.CallbackBaseUri))
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailVerificationFailed,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = request.UserId,
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.InvalidCallbackUri.Value
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.InvalidCallbackUri, $"The URI '{request.CallbackBaseUri}' is not allowed.");
        }

        var user = await _identityContext.Repository.GetUserByIdAsync(request.UserId, cancellationToken);
        if (user is not { IsActive: true })
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailVerificationFailed,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = request.UserId,
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.UserNotFoundOrInactive.Value
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.UserNotFoundOrInactive, "User not found or inactive.");
        }

        if (user.EmailVerifiedAt.HasValue)
        {
            return Result.Success();
        }

        var rateLimit = await _rateLimiter.CheckAsync(new RateLimitAttempt
        {
            Key = $"{RequestPurpose}:{user.Id}",
            Purpose = RequestPurpose,
            Email = user.Email,
            UserId = user.Id.ToString(),
            IpAddress = request.Audit?.IpAddress,
            CorrelationId = request.Audit?.CorrelationId
        }, new RateLimitRule { PermitLimit = 3, Window = TimeSpan.FromHours(1) }, cancellationToken);

        if (!rateLimit.IsAllowed)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailVerificationRateLimited,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = user.Id,
                TenantId = (user as ITenantUser)?.TenantId,
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.RateLimited.Value
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.RateLimited, "Too many requests.");
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
                UserId = user.Id,
                TenantId = (user as ITenantUser)?.TenantId,
                Audit = request.Audit
            }, ct);
        });

        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    /// <summary>
    /// Performs the confirm verification <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="request">The request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<Result> ConfirmVerificationAsync(ConfirmEmailVerificationRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var userId = request.UserId;
        var token = request.Token;
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
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.RateLimited.Value
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.RateLimited, "Too many attempts.");
        }

        var tokenHash = _tokenContext.Hasher.HashToken(token);
        var credential = await _identityContext.Repository.GetCredentialForUserAsync(userId, ProviderType.Internal, ProviderName, tokenHash, cancellationToken);

        var now = _timeProvider.GetUtcNow();
        if (credential == null || !credential.IsAvailable(now))
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailVerificationFailed,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.InvalidOrExpiredToken.Value
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.InvalidOrExpiredToken, "Invalid or expired token.");
        }

        await using var transaction = await _identityContext.TransactionProvider.BeginTransactionAsync(cancellationToken);

        var consumed = await _identityContext.Repository.ConsumeCredentialAsync(credential.Id, credential.Version, cancellationToken);
        if (!consumed)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailVerificationFailed,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.TokenConsumptionFailed.Value
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.TokenConsumptionFailed, "Invalid or expired token.");
        }

        var user = await _identityContext.Repository.GetUserByIdAsync(userId, cancellationToken);
        if (user is not { IsActive: true })
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailVerificationFailed,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.UserNotFoundOrInactive.Value
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.UserNotFoundOrInactive, "Invalid or expired token.");
        }

        var updatedUser = new UpdatedUserWrapper(user, now);
        await _identityContext.Repository.UpdateUserAsync(updatedUser, cancellationToken);

        transaction.OnCommitted(async ct =>
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailVerified,
                Outcome = SecurityEventOutcomes.Success,
                UserId = userId,
                TenantId = (updatedUser as ITenantUser)?.TenantId,
                Audit = request.Audit
            }, ct);

            await _notifications.NotifyAsync(SecurityNotificationType.EmailVerificationCompleted, updatedUser, now, cancellationToken: ct);
        });

        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    private sealed class UpdatedUserWrapper(IUser original, DateTimeOffset? emailVerifiedAt) : ITenantUser, IHasAuditMetadata
    {
        /// <summary>
        /// Gets or sets the id value.
        /// </summary>
        public Guid Id => original.Id;
        /// <summary>
        /// Gets or sets the email value.
        /// </summary>
        public string Email => original.Email;
        /// <summary>
        /// Gets or sets the name value.
        /// </summary>
        public string? Name => original.Name;
        /// <summary>
        /// Gets or sets the is active value.
        /// </summary>
        public bool IsActive => original.IsActive;
        /// <summary>
        /// Gets or sets the tenant id value.
        /// </summary>
        public Guid? TenantId => (original as ITenantUser)?.TenantId;
        /// <summary>
        /// Gets or sets the email verified at value.
        /// </summary>
        public DateTimeOffset? EmailVerifiedAt { get; } = emailVerifiedAt;
        /// <summary>
        /// Gets or sets the created at value.
        /// </summary>
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

/// <summary>
/// Provides email verification service dependencies behavior.
/// </summary>
/// <param name="identityContext">The identity context value.</param>
/// <param name="tokenContext">The token context value.</param>
/// <param name="infrastructure">The infrastructure value.</param>
/// <param name="audit">The audit value.</param>
/// <param name="options">The options value.</param>
internal sealed class EmailVerificationServiceDependencies(
    IdentityContext identityContext,
    SecureTokenContext tokenContext,
    IdentityInfrastructureContext infrastructure,
    IdentityAuditContext audit,
    IOptions<EmailVerificationOptions>? options = null)
{
    /// <summary>
    /// Gets the configured dependency value.
    /// </summary>
    public IdentityContext IdentityContext { get; } = identityContext ?? throw new ArgumentNullException(nameof(identityContext));
    /// <summary>
    /// Gets the configured dependency value.
    /// </summary>
    public SecureTokenContext TokenContext { get; } = tokenContext ?? throw new ArgumentNullException(nameof(tokenContext));
    /// <summary>
    /// Gets the configured dependency value.
    /// </summary>
    public IdentityInfrastructureContext Infrastructure { get; } = infrastructure ?? throw new ArgumentNullException(nameof(infrastructure));
    /// <summary>
    /// Gets the configured dependency value.
    /// </summary>
    public IdentityAuditContext Audit { get; } = audit ?? throw new ArgumentNullException(nameof(audit));
    /// <summary>
    /// Gets or sets the options value.
    /// </summary>
    public IOptions<EmailVerificationOptions>? Options { get; } = options;
    /// <summary>
    /// Gets or sets the email sender value.
    /// </summary>
    public IEmailSender EmailSender => Infrastructure.EmailSender;
    /// <summary>
    /// Gets or sets the rate limiter value.
    /// </summary>
    public IAuthenticationRateLimiter RateLimiter => Infrastructure.RateLimiter;
    /// <summary>
    /// Gets or sets the uri validator value.
    /// </summary>
    public IUriValidator UriValidator => Infrastructure.UriValidator;
    /// <summary>
    /// Gets or sets the time provider value.
    /// </summary>
    public TimeProvider TimeProvider => Audit.TimeProvider;
    /// <summary>
    /// Gets or sets the security event sink value.
    /// </summary>
    public ISecurityEventSink SecurityEventSink => Audit.SecurityEventSink;
    /// <summary>
    /// Gets or sets the notification service value.
    /// </summary>
    public ISecurityNotificationService? NotificationService => Audit.NotificationService;
}



