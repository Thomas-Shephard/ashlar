using Ashlar.Auditing;
using Ashlar.Identity.RateLimiting;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Messaging;
using Ashlar.Security.Tokens;
using Ashlar.Identity.Notifications;
using Microsoft.Extensions.Options;
using System.Text.Json;

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
    private readonly IAuthenticationSessionRepository _sessions;

    /// <summary>
    /// Creates the email verification service with the dependencies for token issuance, delivery, and confirmation.
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
        _sessions = dependencies.SessionRepository;
    }

    /// <summary>
    /// Requests a verification email for an active, unverified user.
    /// </summary>
    /// <param name="request">Ashlar-issued validated session, callback base URI, and required matching audit actor.</param>
    /// <param name="cancellationToken">A token that can cancel the request.</param>
    /// <returns>A success result when the verification message is queued or sent; otherwise, a failure describing why the request was rejected.</returns>
    public async Task<Result> RequestVerificationAsync(EmailVerificationRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Session);
        ArgumentNullException.ThrowIfNull(request.Audit);
        var userId = request.Session.UserId;
        var tenantId = request.Session.TenantId;

        if (request.Audit.ActorUserId != userId)
            return await RejectRequestAsync(request, AshlarFailureCodes.ValidationError, "Audit actor must match the validated session user.", cancellationToken);

        var session = await _sessions.GetSessionAsync(request.Session.Id, cancellationToken);
        if (session is null || session.Id != request.Session.Id || session.UserId != userId || !Nullable.Equals(session.TenantId, tenantId)
            || !session.IsActive(_timeProvider.GetUtcNow()))
            return await RejectRequestAsync(request, AshlarFailureCodes.SessionNotFoundOrInactive, null, cancellationToken);

        if (!_uriValidator.IsValid(request.CallbackBaseUri))
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailVerificationFailed,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                TenantId = tenantId,
                SessionId = request.Session.Id,
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.InvalidCallbackUri.Value
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.InvalidCallbackUri, $"The URI '{request.CallbackBaseUri}' is not allowed.");
        }

        var user = await _identityContext.UserRepository.GetUserByIdAsync(userId, cancellationToken);
        if (user == null || !user.CanSignIn() || !UserTenantOwnership.Matches(user, tenantId))
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailVerificationFailed,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                TenantId = tenantId,
                SessionId = request.Session.Id,
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
            Email = user.DisplayEmail,
            UserId = user.Id,
            TenantId = GetTenantId(user),
            Context = EmailFlowRateLimitHelpers.ToAuthenticationContext(request.Audit)
        }, cancellationToken);

        if (!rateLimit.IsAllowed)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailVerificationRateLimited,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = user.Id,
                TenantId = GetTenantId(user),
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
            Purpose = CredentialPurpose,
            Metadata = JsonSerializer.Serialize(new EmailVerificationCredentialMetadata(
                IdentityNormalization.NormalizeEmail(user.DisplayEmail)))
        };

        await using var transaction = await _identityContext.TransactionProvider.BeginTransactionAsync(cancellationToken);

        await _identityContext.CredentialRepository.RevokeCredentialsAsync(user.Id, ProviderType.Internal, ProviderName, cancellationToken);
        await _identityContext.CredentialRepository.CreateOrReplaceCredentialAsync(credential, cancellationToken);

        var callbackUrl = IdentityUrlHelper.ConstructCallbackUrl(request.CallbackBaseUri, _options.Value.TokenParameterName, token, user.Id, _options.Value.UserIdParameterName);
        var message = IdentityUrlHelper.FormatEmailBody(_options.Value.EmailTextTemplate, callbackUrl, "Verification token", token);
        var emailMessage = new EmailMessage(
            user.DisplayEmail,
            _options.Value.Subject, EmailMessageSensitivity.ContainsLiveSecret,
            message,
            options: new EmailMessageOptions
            {
                From = _options.Value.FromAddress,
            });
        await TransactionalEmailDelivery.SendOrRegisterPostCommitAsync(_emailSender, transaction, emailMessage, cancellationToken);

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.EmailVerificationRequested,
            Outcome = SecurityEventOutcomes.Success,
            UserId = user.Id,
            TenantId = GetTenantId(user),
            SessionId = request.Session.Id,
            Audit = request.Audit
        }, cancellationToken);

        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    private async Task<Result> RejectRequestAsync(EmailVerificationRequest request, AshlarFailureCode code, string? message, CancellationToken cancellationToken)
    {
        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.EmailVerificationFailed,
            Outcome = SecurityEventOutcomes.Failure,
            UserId = request.Session.UserId,
            TenantId = request.Session.TenantId,
            SessionId = request.Session.Id,
            Audit = request.Audit with { ActorUserId = request.Session.UserId },
            FailureReason = code.Value
        }, cancellationToken);
        return message is null ? Result.Failure(code) : Result.Failure(code, message);
    }

    /// <summary>
    /// Confirms a verification token and marks the user's email address as verified.
    /// </summary>
    /// <param name="request">Confirmation request containing the raw token and user identifier. Do not log or persist the token.</param>
    /// <param name="cancellationToken">A token that can cancel confirmation.</param>
    /// <returns>A success result when the token is consumed and the email is marked verified; otherwise, a failure describing why confirmation was rejected.</returns>
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

        try
        {
            await _identityContext.CredentialRepository.AcquireUserMutationLockAsync(userId, cancellationToken);
        }
        catch (UserMutationLockNotFoundException)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailVerificationFailed,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.UserNotFoundOrUnavailable.Value
            }, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return Result.Failure(AshlarFailureCodes.UserNotFoundOrUnavailable, InvalidOrExpiredTokenMessage);
        }
        var user = (await _identityContext.UserRepository.GetUserByIdAsync(userId, cancellationToken))!;
        EmailVerificationCredentialMetadata? metadata = null;
        try { metadata = JsonSerializer.Deserialize<EmailVerificationCredentialMetadata>(credential.Metadata ?? ""); }
        catch (JsonException)
        {
            // Malformed metadata is handled as an invalid token below.
        }
        if (!user.CanSignIn())
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailVerificationFailed,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.UserNotFoundOrUnavailable.Value
            }, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return Result.Failure(AshlarFailureCodes.UserNotFoundOrUnavailable, InvalidOrExpiredTokenMessage);
        }

        if (metadata?.NormalizedEmail != IdentityNormalization.NormalizeEmail(user.DisplayEmail))
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailVerificationFailed,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.InvalidOrExpiredToken.Value
            }, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return Result.Failure(AshlarFailureCodes.InvalidOrExpiredToken, InvalidOrExpiredTokenMessage);
        }

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
            await transaction.CommitAsync(cancellationToken);
            return Result.Failure(AshlarFailureCodes.TokenConsumptionFailed, InvalidOrExpiredTokenMessage);
        }

        var updatedUser = new UpdatedUserWrapper(user, now);
        await _identityContext.UserRepository.UpdateUserAsync(updatedUser, cancellationToken);

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.EmailVerified,
            Outcome = SecurityEventOutcomes.Success,
            UserId = userId,
            TenantId = GetTenantId(updatedUser),
            Audit = request.Audit
        }, cancellationToken);

        transaction.OnCommitted(async ct =>
        {
            await _notifications.NotifyAsync(SecurityNotificationType.EmailVerificationCompleted, updatedUser, now, cancellationToken: ct);
        });

        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    private static Guid? GetTenantId(IUser user)
    {
        return user is ITenantUser { TenantId: { } tenantId } ? tenantId : null;
    }

    private sealed record EmailVerificationCredentialMetadata(string NormalizedEmail);

    private sealed class UpdatedUserWrapper(IUser original, DateTimeOffset? emailVerifiedAt) : ITenantUser, IHasAuditMetadata
    {
        /// <summary>
        /// Existing user identifier.
        /// </summary>
        public Guid Id => original.Id;
        /// <summary>
        /// Existing sanitized display/delivery email address.
        /// </summary>
        public string DisplayEmail => original.DisplayEmail;
        /// <summary>
        /// Existing display name.
        /// </summary>
        public string? Name => original.Name;
        /// <summary>
        /// Existing account state.
        /// </summary>
        public UserAccountState AccountState => original.AccountState;
        /// <summary>
        /// Tenant that owns the user.
        /// </summary>
        public Guid? TenantId => GetTenantId(original);
        /// <summary>
        /// Timestamp assigned when the email address is verified.
        /// </summary>
        public DateTimeOffset? EmailVerifiedAt { get; } = emailVerifiedAt;
        /// <summary>
        /// Original user creation timestamp.
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
    IAuthenticationSessionRepository sessionRepository,
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
    /// <summary>Gets authoritative session persistence used to re-check the issuance capability.</summary>
    public IAuthenticationSessionRepository SessionRepository { get; } = sessionRepository ?? throw new ArgumentNullException(nameof(sessionRepository));
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
