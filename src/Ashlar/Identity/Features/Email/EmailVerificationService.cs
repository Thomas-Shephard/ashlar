using Ashlar.Auditing;
using Ashlar.Identity.RateLimiting;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Messaging;
using Ashlar.Security.Tokens;
using Ashlar.Identity.Notifications;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity.Features.Email;

/// <summary>
/// Issues and confirms one-time email verification tokens.
/// </summary>
internal sealed class EmailVerificationService : IEmailVerificationService
{
    private const string RequestPurpose = "email-verification-request";
    private const string VerifyPurpose = "email-verification-verify";
    private const string CredentialPurpose = "email-verification";
    private const string ProviderName = "email-verification";
    private const string InvalidOrExpiredTokenMessage = "Invalid or expired token.";
    private readonly IdentityContext _identityContext;
    private readonly SecureTokenContext _tokenContext;
    private readonly IEmailSender _emailSender;
    private readonly AuthenticationRateLimitChecker _rateLimitChecker;
    private readonly IUriValidator _uriValidator;
    private readonly TimeProvider _timeProvider;
    private readonly SecurityEventEmitter _securityEvents;
    private readonly IOptions<EmailVerificationOptions> _options;
    private readonly SecurityNotificationEmitter _notifications;
    private readonly EmailFlowVerificationRateLimitChecker _verificationRateLimits;

    /// <summary>
    /// Initializes a new instance of the email verification service class.
    /// </summary>
    /// <param name="dependencies">The dependencies required by the email verification workflow.</param>
    public EmailVerificationService(EmailVerificationServiceDependencies dependencies)
    {
        ArgumentNullException.ThrowIfNull(dependencies);

        _identityContext = dependencies.IdentityContext;
        _tokenContext = dependencies.TokenContext;
        _emailSender = dependencies.EmailSender;
        _rateLimitChecker = new AuthenticationRateLimitChecker(dependencies.RateLimiter);
        _uriValidator = dependencies.UriValidator;
        _timeProvider = dependencies.TimeProvider;
        _securityEvents = new SecurityEventEmitter(dependencies.SecurityEventSink, dependencies.TimeProvider);
        _options = dependencies.Options ?? Options.Create(new EmailVerificationOptions());
        _notifications = new SecurityNotificationEmitter(dependencies.NotificationService);
        _verificationRateLimits = new EmailFlowVerificationRateLimitChecker(_rateLimitChecker, VerifyPurpose);
    }

    /// <summary>
    /// Requests a verification email for an active, unverified user.
    /// </summary>
    /// <param name="request">The verification request.</param>
    /// <param name="cancellationToken">A token that can cancel the request.</param>
    /// <returns>A success result when a verification message is queued; otherwise, a failure describing the problem.</returns>
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

        var user = await _identityContext.UserRepository.GetUserByIdAsync(request.UserId, cancellationToken);
        if (user == null || !user.CanSignIn())
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailVerificationFailed,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = request.UserId,
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.UserNotFoundOrUnavailable.Value
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.UserNotFoundOrUnavailable, "User was not found or cannot currently sign in.");
        }

        if (user.EmailVerifiedAt.HasValue)
        {
            return Result.Success();
        }

        var userBucket = AuthenticationRateLimitDimensions.User(user.Id);
        var rateLimit = await _rateLimitChecker.CheckAsync(new AuthenticationRateLimitCheck(RequestPurpose, AuthenticationRateLimitDimensions.DimensionName(userBucket), userBucket, _options.Value.RequestRateLimit)
        {
            Email = user.Email,
            UserId = user.Id,
            TenantId = (user as ITenantUser)?.TenantId,
            Context = EmailFlowRateLimitHelpers.ToAuthenticationContext(request.Audit)
        }, cancellationToken);

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

        await _identityContext.CredentialRepository.RevokeCredentialsAsync(user.Id, ProviderType.Internal, ProviderName, cancellationToken);
        await _identityContext.CredentialRepository.CreateOrReplaceCredentialAsync(credential, cancellationToken);

        var callbackUrl = IdentityUrlHelper.ConstructCallbackUrl(request.CallbackBaseUri, _options.Value.TokenParameterName, token, user.Id, _options.Value.UserIdParameterName);
        var message = IdentityUrlHelper.FormatEmailBody(_options.Value.EmailTextTemplate, callbackUrl, "Verification token", token);
        var emailMessage = new EmailMessage(
            user.Email,
            _options.Value.Subject,
            message,
            options: new EmailMessageOptions
            {
                From = _options.Value.FromAddress,
                Sensitivity = EmailMessageSensitivity.ContainsLiveSecret
            });
        await TransactionalEmailDelivery.SendOrRegisterPostCommitAsync(_emailSender, transaction, emailMessage, cancellationToken);

        transaction.OnCommitted(async ct =>
        {
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
    /// Confirms a verification token and marks the user's email address as verified.
    /// </summary>
    /// <param name="request">The confirmation request containing the token and user id.</param>
    /// <param name="cancellationToken">A token that can cancel confirmation.</param>
    /// <returns>A success result when the token is consumed; otherwise, a failure describing the problem.</returns>
    public async Task<Result> ConfirmVerificationAsync(ConfirmEmailVerificationRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var userId = request.UserId;
        var token = request.Token;

        var context = EmailFlowRateLimitHelpers.ToAuthenticationContext(request.Audit);
        var rateLimit = await _verificationRateLimits.CheckAsync(AuthenticationRateLimitDimensions.Source(context), userId, context, _options.Value.VerificationRateLimit, cancellationToken);

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

        if (!SecureTokenHashing.TryHashToken(_tokenContext.Hasher, token, out var tokenHash))
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailVerificationFailed,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.InvalidOrExpiredToken.Value
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.InvalidOrExpiredToken, InvalidOrExpiredTokenMessage);
        }

        var tokenRateLimit = await _verificationRateLimits.CheckAsync(AuthenticationRateLimitDimensions.TokenHash(tokenHash), userId, context, _options.Value.VerificationRateLimit, cancellationToken);
        if (!tokenRateLimit.IsAllowed)
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

        var userRateLimit = await _verificationRateLimits.CheckAsync(AuthenticationRateLimitDimensions.User(userId), userId, context, _options.Value.VerificationRateLimit, cancellationToken);
        if (!userRateLimit.IsAllowed)
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

        var credential = await _identityContext.CredentialRepository.GetCredentialForUserAsync(userId, ProviderType.Internal, ProviderName, tokenHash, cancellationToken);

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
            return Result.Failure(AshlarFailureCodes.InvalidOrExpiredToken, InvalidOrExpiredTokenMessage);
        }

        await using var transaction = await _identityContext.TransactionProvider.BeginTransactionAsync(cancellationToken);

        var consumed = await _identityContext.CredentialRepository.ConsumeCredentialAsync(credential.Id, credential.Version, cancellationToken);
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
            return Result.Failure(AshlarFailureCodes.TokenConsumptionFailed, InvalidOrExpiredTokenMessage);
        }

        var user = await _identityContext.UserRepository.GetUserByIdAsync(userId, cancellationToken);
        if (user == null || !user.CanSignIn())
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailVerificationFailed,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.UserNotFoundOrUnavailable.Value
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.UserNotFoundOrUnavailable, InvalidOrExpiredTokenMessage);
        }

        var updatedUser = new UpdatedUserWrapper(user, now);
        await _identityContext.UserRepository.UpdateUserAsync(updatedUser, cancellationToken);

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
        /// Gets the user identifier.
        /// </summary>
        public Guid Id => original.Id;
        /// <summary>
        /// Gets the user's email address.
        /// </summary>
        public string Email => original.Email;
        /// <summary>
        /// Gets the user's display name.
        /// </summary>
        public string? Name => original.Name;
        /// <summary>
        /// Gets the user's account state.
        /// </summary>
        public UserAccountState AccountState => original.AccountState;
        /// <summary>
        /// Gets the tenant that owns the user.
        /// </summary>
        public Guid? TenantId => (original as ITenantUser)?.TenantId;
        /// <summary>
        /// Gets the timestamp assigned when the email address is verified.
        /// </summary>
        public DateTimeOffset? EmailVerifiedAt { get; } = emailVerifiedAt;
        /// <summary>
        /// Gets the original user creation timestamp.
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
/// Groups dependencies used by <see cref="EmailVerificationService" />.
/// </summary>
/// <param name="identityContext">User, credential, identity, and transaction dependencies.</param>
/// <param name="tokenContext">Token generation and hashing dependencies.</param>
/// <param name="infrastructure">Email, rate limiting, and URI validation dependencies.</param>
/// <param name="audit">Time, security event, and notification dependencies.</param>
/// <param name="options">Optional email verification configuration.</param>
internal sealed class EmailVerificationServiceDependencies(
    IdentityContext identityContext,
    SecureTokenContext tokenContext,
    IdentityInfrastructureContext infrastructure,
    IdentityAuditContext audit,
    IOptions<EmailVerificationOptions>? options = null)
{
    /// <summary>
    /// Gets identity persistence and transaction dependencies.
    /// </summary>
    public IdentityContext IdentityContext { get; } = identityContext ?? throw new ArgumentNullException(nameof(identityContext));
    /// <summary>
    /// Gets token generation and hashing dependencies.
    /// </summary>
    public SecureTokenContext TokenContext { get; } = tokenContext ?? throw new ArgumentNullException(nameof(tokenContext));
    /// <summary>
    /// Gets email, rate limiting, and URI validation dependencies.
    /// </summary>
    public IdentityInfrastructureContext Infrastructure { get; } = infrastructure ?? throw new ArgumentNullException(nameof(infrastructure));
    /// <summary>
    /// Gets audit and notification dependencies.
    /// </summary>
    public IdentityAuditContext Audit { get; } = audit ?? throw new ArgumentNullException(nameof(audit));
    /// <summary>
    /// Gets email verification options.
    /// </summary>
    public IOptions<EmailVerificationOptions>? Options { get; } = options;
    /// <summary>
    /// Gets the email sender.
    /// </summary>
    public IEmailSender EmailSender => Infrastructure.EmailSender;
    /// <summary>
    /// Gets the authentication rate limiter.
    /// </summary>
    public IAuthenticationRateLimiter RateLimiter => Infrastructure.RateLimiter;
    /// <summary>
    /// Gets the URI validator.
    /// </summary>
    public IUriValidator UriValidator => Infrastructure.UriValidator;
    /// <summary>
    /// Gets the time provider.
    /// </summary>
    public TimeProvider TimeProvider => Audit.TimeProvider;
    /// <summary>
    /// Gets the security event sink.
    /// </summary>
    public ISecurityEventSink SecurityEventSink => Audit.SecurityEventSink;
    /// <summary>
    /// Gets the security notification service.
    /// </summary>
    public ISecurityNotificationService? NotificationService => Audit.NotificationService;
}
