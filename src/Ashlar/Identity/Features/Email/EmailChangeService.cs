using Ashlar.Auditing;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.RateLimiting;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Messaging;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity.Features.Email;

/// <summary>
/// Coordinates verified email-address changes for existing users.
/// </summary>
/// <param name="dependencies">Dependencies used to create, store, and verify email-change credentials.</param>
/// <param name="options">Email-change token and delivery options.</param>
/// <param name="logger">Logger for email-change failures.</param>
internal sealed class EmailChangeService(
    EmailChangeDependencies dependencies,
    IOptions<EmailChangeOptions>? options = null,
    ILogger<EmailChangeService>? logger = null)
    : IEmailChangeService
{
    private static readonly Action<ILogger, Guid, Guid, Exception?> EmailChangeCredentialUnprotectFailed =
        LoggerMessage.Define<Guid, Guid>(
            LogLevel.Warning,
            new EventId(1000, nameof(EmailChangeCredentialUnprotectFailed)),
            "Email change credential unprotection failed. UserId={UserId} CredentialId={CredentialId}");

    private const string RequestPurpose = "email-change-request";
    private const string VerifyPurpose = "email-change-verify";
    private const string CredentialPurpose = "email-change";
    private const string ProviderName = "email-change";
    private const string InvalidOrExpiredTokenMessage = "Invalid or expired token.";
    private readonly EmailChangeDependencies _dependencies = dependencies ?? throw new ArgumentNullException(nameof(dependencies));
    private readonly SecurityEventEmitter _securityEvents = new(dependencies.SecurityEventSink, dependencies.TimeProvider);
    private readonly IOptions<EmailChangeOptions> _options = options ?? Options.Create(new EmailChangeOptions());
    private readonly SecurityNotificationEmitter _notifications = new(dependencies.NotificationService);
    private readonly ILogger<EmailChangeService> _logger = logger ?? NullLogger<EmailChangeService>.Instance;
    private readonly AuthenticationRateLimitChecker _rateLimitChecker = new(dependencies.RateLimiter);
    private readonly EmailFlowVerificationRateLimitChecker _verificationRateLimits = new(new AuthenticationRateLimitChecker(dependencies.RateLimiter), VerifyPurpose);

    /// <summary>
    /// Creates an email-change verification credential and sends the confirmation message.
    /// </summary>
    /// <param name="request">Email-change request details.</param>
    /// <param name="cancellationToken">A token that can cancel credential creation, message delivery, or audit work.</param>
    /// <returns>A success result when the email-change confirmation message is queued; otherwise, a failure describing why the request was rejected.</returns>
    public async Task<Result> RequestChangeAsync(RequestEmailChangeRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!_dependencies.UriValidator.IsValid(request.CallbackBaseUri))
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailChangeFailed,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = request.UserId,
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.InvalidCallbackUri.Value
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.InvalidCallbackUri, $"The URI '{request.CallbackBaseUri}' is not allowed.");
        }

        var user = await _dependencies.IdentityContext.UserRepository.GetUserByIdAsync(request.UserId, cancellationToken);
        if (user == null || !user.CanSignIn())
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailChangeFailed,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = request.UserId,
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.UserNotFoundOrUnavailable.Value
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.UserNotFoundOrUnavailable, "User was not found or cannot currently sign in.");
        }

        var newEmail = IdentityNormalization.SanitizeEmailForDelivery(request.NewEmail);
        var normalizedNewEmail = IdentityNormalization.NormalizeEmail(newEmail);
        if (normalizedNewEmail == IdentityNormalization.NormalizeEmail(user.DisplayEmail))
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailChangeFailed,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = user.Id,
                TenantId = GetTenantId(user),
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.SameEmail.Value
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.SameEmail, "New email must be different from the current email.");
        }

        var userBucket = AuthenticationRateLimitDimensions.User(user.Id);
        var rateLimit = await _rateLimitChecker.CheckAsync(new AuthenticationRateLimitCheck(RequestPurpose, AuthenticationRateLimitDimensions.DimensionName(userBucket), userBucket, _options.Value.RequestRateLimit)
        {
            UserId = user.Id,
            TenantId = GetTenantId(user),
            Context = EmailFlowRateLimitHelpers.ToAuthenticationContext(request.Audit)
        }, cancellationToken);

        if (!rateLimit.IsAllowed)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailChangeRateLimited,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = user.Id,
                TenantId = GetTenantId(user),
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.RateLimited.Value
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.RateLimited, "Too many requests.");
        }

        var existingUser = await _dependencies.IdentityContext.UserRepository.GetUserByEmailAsync(
            newEmail,
            GetTenantId(user),
            cancellationToken);
        if (existingUser != null) return await SuppressEmailChangeRequestAsync(newEmail, user, request.Audit, cancellationToken);

        var token = _dependencies.TokenContext.Generator.GenerateToken();
        var tokenHash = _dependencies.TokenContext.Hasher.HashToken(token);
        var now = _dependencies.TimeProvider.GetUtcNow();

        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.Internal,
            ProviderName = ProviderName,
            ProviderKey = tokenHash,
            Version = Guid.NewGuid().ToString("N"),
            CredentialValue = _dependencies.SecretProtector.Protect(newEmail),
            CreatedAt = now,
            ExpiresAt = now.Add(_options.Value.Expiration),
            Status = CredentialStatus.Active,
            Purpose = CredentialPurpose
        };

        await using var transaction = await _dependencies.IdentityContext.TransactionProvider.BeginTransactionAsync(cancellationToken);

        await _dependencies.IdentityContext.CredentialRepository.RevokeCredentialsAsync(user.Id, ProviderType.Internal, ProviderName, cancellationToken);
        await _dependencies.IdentityContext.CredentialRepository.CreateOrReplaceCredentialAsync(credential, cancellationToken);

        var callbackUrl = IdentityUrlHelper.ConstructCallbackUrl(request.CallbackBaseUri, _options.Value.TokenParameterName, token, user.Id, _options.Value.UserIdParameterName);
        var message = IdentityUrlHelper.FormatEmailBody(_options.Value.EmailTextTemplate, callbackUrl, "Confirmation token", token);
        var emailMessage = new EmailMessage(
            newEmail,
            _options.Value.Subject,
            message,
            options: new EmailMessageOptions
            {
                From = _options.Value.FromAddress,
                Sensitivity = EmailMessageSensitivity.ContainsLiveSecret
            });
        await TransactionalEmailDelivery.SendOrRegisterPostCommitAsync(_dependencies.EmailSender, transaction, emailMessage, cancellationToken);

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.EmailChangeRequested,
            Outcome = SecurityEventOutcomes.Success,
            UserId = user.Id,
            TenantId = GetTenantId(user),
            Audit = request.Audit,
            Properties = new Dictionary<string, string> { ["new_email"] = newEmail }
        }, cancellationToken);

        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    private async Task<Result> SuppressEmailChangeRequestAsync(string newEmail, IUser user, AuditContext? audit, CancellationToken cancellationToken)
    {
        await using var suppressionTransaction = await _dependencies.IdentityContext.TransactionProvider.BeginTransactionAsync(cancellationToken);
        var suppressionMessage = new EmailMessage(
            newEmail,
            _options.Value.Subject,
            "An attempt was made to change another account's email address to this one. No changes were made, and no further action is required.",
            options: new EmailMessageOptions { From = _options.Value.FromAddress });

        await TransactionalEmailDelivery.SendOrRegisterPostCommitAsync(_dependencies.EmailSender, suppressionTransaction, suppressionMessage, cancellationToken);

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.EmailChangeRequestSuppressed,
            Outcome = SecurityEventOutcomes.Success,
            UserId = user.Id,
            TenantId = GetTenantId(user),
            Audit = audit,
            FailureReason = AshlarFailureCodes.EmailAlreadyInUse.Value
        }, cancellationToken);

        await suppressionTransaction.CommitAsync(cancellationToken);
        return Result.Success();
    }

    /// <summary>
    /// Consumes an email-change credential and updates the user's email address.
    /// </summary>
    /// <param name="request">Email-change confirmation details.</param>
    /// <param name="cancellationToken">A token that can cancel token verification or email update work.</param>
    /// <returns>A success result when the token is consumed and the email address is updated; otherwise, a failure describing why confirmation was rejected.</returns>
    public async Task<Result> ConfirmChangeAsync(ConfirmEmailChangeRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var context = EmailFlowRateLimitHelpers.ToAuthenticationContext(request.Audit);
        var rateLimit = await _verificationRateLimits.CheckAsync(AuthenticationRateLimitDimensions.Source(context), request.UserId, context, _options.Value.VerificationRateLimit, cancellationToken);

        if (!rateLimit.IsAllowed)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailChangeVerificationRateLimited,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = request.UserId,
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.RateLimited.Value
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.RateLimited, "Too many attempts.");
        }

        if (!SecureTokenHashing.TryHashToken(_dependencies.TokenContext.Hasher, request.Token, out var tokenHash))
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailChangeFailed,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = request.UserId,
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.InvalidOrExpiredToken.Value
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.InvalidOrExpiredToken, InvalidOrExpiredTokenMessage);
        }

        var tokenRateLimit = await _verificationRateLimits.CheckAsync(AuthenticationRateLimitDimensions.TokenHash(tokenHash), request.UserId, context, _options.Value.VerificationRateLimit, cancellationToken);
        if (!tokenRateLimit.IsAllowed)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailChangeVerificationRateLimited,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = request.UserId,
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.RateLimited.Value
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.RateLimited, "Too many attempts.");
        }

        var userRateLimit = await _verificationRateLimits.CheckAsync(AuthenticationRateLimitDimensions.User(request.UserId), request.UserId, context, _options.Value.VerificationRateLimit, cancellationToken);
        if (!userRateLimit.IsAllowed)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailChangeVerificationRateLimited,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = request.UserId,
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.RateLimited.Value
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.RateLimited, "Too many attempts.");
        }

        var credential = await _dependencies.IdentityContext.CredentialRepository.GetCredentialForUserAsync(request.UserId, ProviderType.Internal, ProviderName, tokenHash, cancellationToken);

        var now = _dependencies.TimeProvider.GetUtcNow();
        if (credential == null || !credential.IsAvailable(now) || string.IsNullOrWhiteSpace(credential.CredentialValue))
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailChangeFailed,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = request.UserId,
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.InvalidOrExpiredToken.Value
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.InvalidOrExpiredToken, InvalidOrExpiredTokenMessage);
        }

        string newEmail;
        try
        {
            newEmail = IdentityNormalization.SanitizeEmailForDelivery(_dependencies.SecretProtector.Unprotect(credential.CredentialValue));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            EmailChangeCredentialUnprotectFailed(_logger, request.UserId, credential.Id, ex);
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailChangeFailed,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = request.UserId,
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.InvalidTokenData.Value
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.InvalidTokenData, "Invalid token data.");
        }

        await using var transaction = await _dependencies.IdentityContext.TransactionProvider.BeginTransactionAsync(cancellationToken);

        var user = await _dependencies.IdentityContext.UserRepository.GetUserByIdAsync(request.UserId, cancellationToken);
        if (user == null || !user.CanSignIn())
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailChangeFailed,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = request.UserId,
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.UserNotFoundOrUnavailable.Value
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.UserNotFoundOrUnavailable, InvalidOrExpiredTokenMessage);
        }

        var consumed = await _dependencies.IdentityContext.CredentialRepository.ConsumeCredentialAsync(credential.Id, credential.Version, cancellationToken);
        if (!consumed)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailChangeFailed,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = request.UserId,
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.TokenConsumptionFailed.Value
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.TokenConsumptionFailed, InvalidOrExpiredTokenMessage);
        }

        var tenantId = GetTenantId(user);
        var existingUser = await _dependencies.IdentityContext.UserRepository.GetUserByEmailAsync(newEmail, tenantId, cancellationToken);
        if (existingUser != null && existingUser.Id != user.Id)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailChangeFailed,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = user.Id,
                TenantId = tenantId,
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.EmailAlreadyInUse.Value
            }, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return Result.Failure(AshlarFailureCodes.EmailAlreadyInUse, "New email is already in use.");
        }

        var oldDisplayEmail = user.DisplayEmail;
        var updatedUser = new UpdatedUserWrapper(user, newEmail, now);

        await _dependencies.IdentityContext.UserRepository.UpdateUserAsync(updatedUser, cancellationToken);

        if (_options.Value.RevokeSessions)
        {
            var tenant = tenantId.HasValue ? new TenantContext(tenantId.Value) : TenantContext.Global;
            await _dependencies.SessionRepository.RevokeSessionsForUserAsync(user.Id, now, "Email changed", tenant, includeAllTenants: false, cancellationToken);
        }

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.EmailChanged,
            Outcome = SecurityEventOutcomes.Success,
            UserId = user.Id,
            TenantId = tenantId,
            Audit = request.Audit,
            Properties = new Dictionary<string, string>
            {
                ["old_email"] = oldDisplayEmail,
                ["new_email"] = newEmail
            }
        }, cancellationToken);

        transaction.OnCommitted(async ct =>
        {
            var notificationMetadata = new Dictionary<string, string>
            {
                ["old_email"] = oldDisplayEmail,
                ["new_email"] = newEmail
            };

            await _notifications.NotifyAsync(SecurityNotificationType.EmailChanged, oldDisplayEmail, now, metadata: notificationMetadata, cancellationToken: ct);
            await _notifications.NotifyAsync(SecurityNotificationType.EmailChanged, updatedUser, now, metadata: notificationMetadata, cancellationToken: ct);
        });

        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    private static Guid? GetTenantId(IUser user)
    {
        return user is ITenantUser { TenantId: { } tenantId } ? tenantId : null;
    }

    private sealed class UpdatedUserWrapper(IUser original, string newEmail, DateTimeOffset? emailVerifiedAt) : ITenantUser, IHasAuditMetadata
    {
        /// <summary>
        /// Existing user identifier.
        /// </summary>
        public Guid Id => original.Id;
        /// <summary>
        /// Replacement sanitized display/delivery email address.
        /// </summary>
        public string DisplayEmail { get; } = newEmail;
        /// <summary>
        /// Existing display name.
        /// </summary>
        public string? Name => original.Name;
        /// <summary>
        /// Existing account state.
        /// </summary>
        public UserAccountState AccountState => original.AccountState;
        /// <summary>
        /// Existing tenant identifier.
        /// </summary>
        public Guid? TenantId => GetTenantId(original);
        /// <summary>
        /// Updated email verification timestamp.
        /// </summary>
        public DateTimeOffset? EmailVerifiedAt { get; } = emailVerifiedAt;
        /// <summary>
        /// Existing creation timestamp.
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
