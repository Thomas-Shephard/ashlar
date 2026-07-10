using Ashlar.Auditing;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.Providers;
using Ashlar.Identity.RateLimiting;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Messaging;
using Ashlar.Security.Hashing;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity.Features.Credentials;

/// <summary>
/// Coordinates local password reset requests and completions.
/// </summary>
internal sealed class PasswordResetService : IPasswordResetService
{
    internal const string CredentialPurpose = "password-reset";
    internal const string ProviderName = "password-reset";
    private const string RequestPurpose = "password-reset-request";
    private const string VerifyPurpose = "password-reset-verify";
    private const string SessionRevocationReason = "Password reset";
    private const string EmailRequiredMessage = "Email is required.";
    private const string TooManyRequestsMessage = "Too many requests.";
    private const string PasswordRequiredMessage = "Password is required.";
    private const string TooManyAttemptsMessage = "Too many attempts.";
    private const string InvalidOrExpiredTokenMessage = "Invalid or expired token.";
    private const string RequestSuppressedReason = "request_suppressed";
    private const string DeliveryFailedReason = "delivery_failed";
    private const string ResetTokenLabel = "Reset token";

    private readonly PasswordResetDependencies _dependencies;
    private readonly IOptions<PasswordResetOptions> _options;
    private readonly SecurityEventEmitter _securityEvents;
    private readonly SecurityNotificationEmitter _notifications;
    private readonly AuthenticationRateLimitChecker _rateLimitChecker;

    /// <summary>
    /// Initializes a configured password reset service.
    /// </summary>
    /// <param name="dependencies">The password reset dependency graph.</param>
    /// <param name="options">Optional password reset options.</param>
    public PasswordResetService(
        PasswordResetDependencies dependencies,
        IOptions<PasswordResetOptions>? options = null)
    {
        _dependencies = dependencies ?? throw new ArgumentNullException(nameof(dependencies));
        _options = options ?? Options.Create(new PasswordResetOptions());
        _securityEvents = new SecurityEventEmitter(_dependencies.SecurityEventSink, _dependencies.TimeProvider);
        _notifications = new SecurityNotificationEmitter(_dependencies.NotificationService);
        _rateLimitChecker = new AuthenticationRateLimitChecker(_dependencies.RateLimiter);
    }

    /// <inheritdoc />
    public async Task<Result> RequestPasswordResetAsync(
        string email,
        Uri callbackBaseUri,
        AuthenticationContext? context = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(callbackBaseUri);

        if (string.IsNullOrWhiteSpace(email))
        {
            return Result.Failure(AshlarFailureCodes.ValidationError, EmailRequiredMessage);
        }

        var startedAt = _dependencies.TimeProvider.GetTimestamp();
        var displayEmail = IdentityNormalization.SanitizeEmailForDelivery(email);
        var normalizedEmail = IdentityNormalization.NormalizeEmail(displayEmail);
        context = (context ?? new AuthenticationContext()) with { Email = normalizedEmail };

        if (!_dependencies.UriValidator.IsValid(callbackBaseUri))
        {
            await RecordAsync(
                AshlarSecurityEventTypes.PasswordResetFailed,
                SecurityEventOutcomes.Failure,
                context,
                userId: null,
                AshlarFailureCodes.InvalidCallbackUri.Value,
                cancellationToken);

            return Result.Failure(AshlarFailureCodes.InvalidCallbackUri, $"The URI '{callbackBaseUri}' is not allowed.");
        }

        var sourceRateLimit = await CheckRateLimitAsync(
            AuthenticationRateLimitDimensions.Source(context),
            RequestPurpose,
            context,
            _options.Value.RequestRateLimit,
            cancellationToken);

        if (!sourceRateLimit.IsAllowed)
        {
            await RecordAsync(
                AshlarSecurityEventTypes.PasswordResetRequestRateLimited,
                SecurityEventOutcomes.Failure,
                context,
                userId: null,
                AshlarFailureCodes.RateLimited.Value,
                cancellationToken);

            return Result.Failure(AshlarFailureCodes.RateLimited, TooManyRequestsMessage);
        }

        var rateLimit = await CheckRateLimitAsync(
            AuthenticationRateLimitDimensions.Email(normalizedEmail),
            RequestPurpose,
            context,
            _options.Value.RequestRateLimit,
            cancellationToken);

        if (!rateLimit.IsAllowed)
        {
            await RecordAsync(
                AshlarSecurityEventTypes.PasswordResetRequestRateLimited,
                SecurityEventOutcomes.Failure,
                context,
                userId: null,
                AshlarFailureCodes.RateLimited.Value,
                cancellationToken);

            return Result.Failure(AshlarFailureCodes.RateLimited, TooManyRequestsMessage);
        }

        var user = await _dependencies.IdentityContext.UserRepository.GetUserByEmailAsync(displayEmail, context.TenantId, cancellationToken);
        if (user == null || !user.CanSignIn() || !await HasLocalPasswordCredentialAsync(user.Id, cancellationToken))
        {
            _ = _dependencies.TokenContext.Hasher.HashToken(_dependencies.TokenContext.Generator.GenerateToken());

            await RecordAsync(
                AshlarSecurityEventTypes.PasswordResetRequestSuppressed,
                SecurityEventOutcomes.Success,
                context,
                userId: null,
                RequestSuppressedReason,
                cancellationToken);

            await DelayUntilMinimumRequestDurationAsync(startedAt, cancellationToken);
            return Result.Success();
        }

        await using var transaction = await _dependencies.IdentityContext.TransactionProvider.BeginTransactionAsync(cancellationToken);

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
            CreatedAt = now,
            ExpiresAt = now.Add(_options.Value.Expiration),
            Status = CredentialStatus.Active,
            Purpose = CredentialPurpose
        };

        await _dependencies.IdentityContext.CredentialRepository.RevokeCredentialsAsync(user.Id, ProviderType.Internal, ProviderName, cancellationToken);
        await _dependencies.IdentityContext.CredentialRepository.CreateOrReplaceCredentialAsync(credential, cancellationToken);

        var callbackUrl = IdentityUrlHelper.ConstructCallbackUrl(callbackBaseUri, _options.Value.TokenParameterName, token);
        var message = IdentityUrlHelper.FormatEmailBody(_options.Value.EmailTextTemplate, callbackUrl, ResetTokenLabel, token);
        var resetEmail = new EmailMessage(
            user.DisplayEmail,
            _options.Value.Subject,
            message,
            options: new EmailMessageOptions
            {
                From = _options.Value.FromAddress,
                Sensitivity = EmailMessageSensitivity.ContainsLiveSecret
            });
        var transactionalEmailOutbox = TransactionalEmailDelivery.IsTransactionalDurableOutbox(_dependencies.EmailSender);
        var resetEmailQueued = true;
        if (transactionalEmailOutbox)
        {
            resetEmailQueued = await SendResetEmailOrRevokeAsync(user, resetEmail, context, cancellationToken);
        }

        if (resetEmailQueued)
        {
            await RecordAsync(
                AshlarSecurityEventTypes.PasswordResetRequested,
                SecurityEventOutcomes.Success,
                context,
                user.Id,
                failureReason: null,
                cancellationToken);
        }

        transaction.OnCommitted(async ct =>
        {
            if (!transactionalEmailOutbox)
            {
                await SendResetEmailOrRevokeAsync(user, resetEmail, context, ct);
            }
        });

        await transaction.CommitAsync(cancellationToken);
        await DelayUntilMinimumRequestDurationAsync(startedAt, cancellationToken);
        return Result.Success();
    }

    /// <inheritdoc />
    public async Task<Result<PasswordResetResult>> ResetPasswordAsync(
        PasswordResetRequest request,
        AuthenticationContext? context = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        context ??= new AuthenticationContext();

        if (string.IsNullOrWhiteSpace(request.NewPassword))
        {
            await RecordFailureAsync(context, null, AshlarFailureCodes.InvalidSecret.Value, cancellationToken);
            return Result.Failure<PasswordResetResult>(AshlarFailureCodes.InvalidSecret, PasswordRequiredMessage);
        }

        var rateLimit = await CheckRateLimitAsync(
            AuthenticationRateLimitDimensions.Source(context),
            VerifyPurpose,
            context,
            _options.Value.VerificationRateLimit,
            cancellationToken);

        if (!rateLimit.IsAllowed)
        {
            await RecordAsync(
                AshlarSecurityEventTypes.PasswordResetVerificationRateLimited,
                SecurityEventOutcomes.Failure,
                context,
                userId: null,
                AshlarFailureCodes.RateLimited.Value,
                cancellationToken);

            return Result.Failure<PasswordResetResult>(AshlarFailureCodes.RateLimited, TooManyAttemptsMessage);
        }

        if (!SecureTokenHashing.TryHashToken(_dependencies.TokenContext.Hasher, request.Token, out var tokenHash))
        {
            await RecordFailureAsync(context, null, AshlarFailureCodes.InvalidOrExpiredToken.Value, cancellationToken);
            return Result.Failure<PasswordResetResult>(AshlarFailureCodes.InvalidOrExpiredToken, InvalidOrExpiredTokenMessage);
        }

        var tokenRateLimit = await CheckRateLimitAsync(
            AuthenticationRateLimitDimensions.TokenHash(tokenHash),
            VerifyPurpose,
            context,
            _options.Value.VerificationRateLimit,
            cancellationToken);

        if (!tokenRateLimit.IsAllowed)
        {
            await RecordAsync(
                AshlarSecurityEventTypes.PasswordResetVerificationRateLimited,
                SecurityEventOutcomes.Failure,
                context,
                userId: null,
                AshlarFailureCodes.RateLimited.Value,
                cancellationToken);

            return Result.Failure<PasswordResetResult>(AshlarFailureCodes.RateLimited, TooManyAttemptsMessage);
        }

        var user = await _dependencies.IdentityContext.UserRepository.GetUserByProviderKeyAsync(ProviderType.Internal, ProviderName, tokenHash, cancellationToken);
        if (user == null || !user.CanSignIn() || !UserTenantOwnership.Matches(user, context.TenantId))
        {
            await RecordFailureAsync(context, user?.Id, AshlarFailureCodes.InvalidOrExpiredToken.Value, cancellationToken);
            return Result.Failure<PasswordResetResult>(AshlarFailureCodes.InvalidOrExpiredToken, InvalidOrExpiredTokenMessage);
        }

        var credential = await _dependencies.IdentityContext.CredentialRepository.GetCredentialForUserAsync(user.Id, ProviderType.Internal, ProviderName, tokenHash, cancellationToken);
        var now = _dependencies.TimeProvider.GetUtcNow();
        if (credential == null || credential.Purpose != CredentialPurpose || !credential.IsAvailable(now))
        {
            await RecordFailureAsync(context, user.Id, AshlarFailureCodes.InvalidOrExpiredToken.Value, cancellationToken);
            return Result.Failure<PasswordResetResult>(AshlarFailureCodes.InvalidOrExpiredToken, InvalidOrExpiredTokenMessage);
        }

        await using var transaction = await _dependencies.IdentityContext.TransactionProvider.BeginTransactionAsync(cancellationToken);
        await _dependencies.IdentityContext.CredentialRepository.AcquireUserMutationLockAsync(user.Id, cancellationToken);
        var lockedUser = await _dependencies.IdentityContext.UserRepository.GetUserByIdAsync(user.Id, cancellationToken);
        if (lockedUser == null || !lockedUser.CanSignIn() || !UserTenantOwnership.Matches(lockedUser, context.TenantId))
        {
            await RecordFailureAsync(context, user.Id, AshlarFailureCodes.InvalidOrExpiredToken.Value, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return Result.Failure<PasswordResetResult>(AshlarFailureCodes.InvalidOrExpiredToken, InvalidOrExpiredTokenMessage);
        }
        user = lockedUser;

        var consumed = await _dependencies.IdentityContext.CredentialRepository.ConsumeCredentialAsync(credential.Id, credential.Version, cancellationToken);
        if (!consumed)
        {
            await RecordFailureAsync(context, user.Id, AshlarFailureCodes.TokenConsumptionFailed.Value, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return Result.Failure<PasswordResetResult>(AshlarFailureCodes.TokenConsumptionFailed, InvalidOrExpiredTokenMessage);
        }

        var hashedPassword = PasswordCredentialHashing.HashToBase64(_dependencies.PasswordHasherSelector, request.NewPassword);
        var localCredential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = AuthenticationProviderKey.Local.Type,
            ProviderName = AuthenticationProviderKey.Local.Name,
            ProviderKey = user.Id.ToString("D"),
            Version = Guid.NewGuid().ToString("N"),
            CreatedAt = now,
            UpdatedAt = now,
            Status = CredentialStatus.Active,
            CredentialValue = hashedPassword
        };

        await _dependencies.IdentityContext.CredentialRepository.RevokeCredentialsAsync(user.Id, AuthenticationProviderKey.Local.Type, AuthenticationProviderKey.Local.Name, cancellationToken);
        await _dependencies.IdentityContext.CredentialRepository.CreateOrReplaceCredentialAsync(localCredential, cancellationToken);

        var sessionsRevoked = 0;
        if (_options.Value.RevokeSessions)
        {
            var tenant = context.TenantId.HasValue ? new TenantContext(context.TenantId.Value) : TenantContext.Global;
            sessionsRevoked = await _dependencies.SessionRepository.RevokeSessionsForUserAsync(user.Id, now, SessionRevocationReason, tenant, includeAllTenants: false, cancellationToken);
        }

        await RevokeRememberedMfaDevicesAsync(user.Id, context, cancellationToken);
        var result = new PasswordResetResult(user.Id, sessionsRevoked);
        await RecordAsync(
            AshlarSecurityEventTypes.PasswordResetCompleted,
            SecurityEventOutcomes.Success,
            context,
            user.Id,
            failureReason: null,
            cancellationToken);

        transaction.OnCommitted(async ct =>
        {
            await _notifications.NotifyAsync(SecurityNotificationType.PasswordResetCompleted, user, now, context, cancellationToken: ct);
        });

        await transaction.CommitAsync(cancellationToken);
        return Result.Success(result);
    }

    private async Task<bool> HasLocalPasswordCredentialAsync(Guid userId, CancellationToken cancellationToken)
    {
        var credential = await _dependencies.IdentityContext.CredentialRepository.GetCredentialForUserAsync(
            userId,
            AuthenticationProviderKey.Local.Type,
            AuthenticationProviderKey.Local.Name,
            userId.ToString("D"),
            cancellationToken);

        return credential != null && credential.IsAvailable(_dependencies.TimeProvider.GetUtcNow());
    }

    private Task<RateLimitDecision> CheckRateLimitAsync(
        string key,
        string purpose,
        AuthenticationContext context,
        RateLimitRule rule,
        CancellationToken cancellationToken)
    {
        return _rateLimitChecker.CheckAsync(new AuthenticationRateLimitCheck(purpose, AuthenticationRateLimitDimensions.DimensionName(key), key, rule)
        {
            ProviderKey = AuthenticationProviderKey.Local,
            Context = context
        }, cancellationToken);
    }

    private Task RecordFailureAsync(AuthenticationContext context, Guid? userId, string failureReason, CancellationToken cancellationToken)
    {
        return RecordAsync(
            AshlarSecurityEventTypes.PasswordResetFailed,
            SecurityEventOutcomes.Failure,
            context,
            userId,
            failureReason,
            cancellationToken);
    }

    private Task<int> RevokeRememberedMfaDevicesAsync(Guid userId, AuthenticationContext context, CancellationToken cancellationToken)
    {
        if (_dependencies.RememberedMfaDeviceService == null)
        {
            return Task.FromResult(0);
        }

        return _dependencies.RememberedMfaDeviceService.RevokeAllAsync(
            userId,
            new RevokeAllRememberedMfaDevicesRequest
            {
                Tenant = context.TenantId.HasValue ? new TenantContext(context.TenantId.Value) : null,
                Reason = SessionRevocationReason,
                Audit = new AuditContext(
                    ActorUserId: userId,
                    IpAddress: context.IpAddress,
                    UserAgent: context.UserAgent,
                    CorrelationId: context.CorrelationId)
            },
            cancellationToken);
    }

    private Task RecordAsync(string eventType, string outcome, AuthenticationContext context, Guid? userId, string? failureReason, CancellationToken cancellationToken)
    {
        return _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = eventType,
            Outcome = outcome,
            UserId = userId,
            Provider = AuthenticationProviderKey.Local,
            Context = context,
            FailureReason = failureReason
        }, cancellationToken);
    }

    private async Task<bool> SendResetEmailOrRevokeAsync(IUser user, EmailMessage message, AuthenticationContext context, CancellationToken cancellationToken)
    {
        try
        {
            await _dependencies.EmailSender.SendAsync(message, cancellationToken);
            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await using var transaction = await _dependencies.IdentityContext.TransactionProvider.BeginTransactionAsync(cancellationToken);
            await _dependencies.IdentityContext.CredentialRepository.RevokeCredentialsAsync(user.Id, ProviderType.Internal, ProviderName, cancellationToken);
            await RecordAsync(
                AshlarSecurityEventTypes.PasswordResetFailed,
                SecurityEventOutcomes.Failure,
                context,
                user.Id,
                DeliveryFailedReason,
                cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }

        return false;
    }

    private async Task DelayUntilMinimumRequestDurationAsync(long startedAt, CancellationToken cancellationToken)
    {
        var minimumDuration = _options.Value.MinimumRequestDuration;
        if (minimumDuration <= TimeSpan.Zero)
        {
            return;
        }

        var elapsed = _dependencies.TimeProvider.GetElapsedTime(startedAt);
        if (elapsed >= minimumDuration)
        {
            return;
        }

        await Task.Delay(minimumDuration - elapsed, _dependencies.TimeProvider, cancellationToken);
    }
}

/// <summary>
/// Groups dependencies used by <see cref="PasswordResetService" />.
/// </summary>
/// <param name="identityContext">Core identity dependencies.</param>
/// <param name="tokenContext">Token generation and hashing dependencies.</param>
/// <param name="infrastructure">Email, rate limiting, and URI validation dependencies.</param>
/// <param name="sessionRepository">Session persistence used for revocation.</param>
/// <param name="passwordHasherSelector">Local password hashing selector.</param>
/// <param name="audit">Audit and notification dependencies.</param>
/// <param name="rememberedMfaDeviceService">Remembered MFA device revocation dependency.</param>
internal sealed class PasswordResetDependencies(
    IdentityContext identityContext,
    SecureTokenContext tokenContext,
    IdentityInfrastructureContext infrastructure,
    IAuthenticationSessionRepository sessionRepository,
    PasswordHasherSelector passwordHasherSelector,
    IdentityAuditContext audit,
    IRememberedMfaDeviceMutationExecutor? rememberedMfaDeviceService = null)
{
    /// <summary>
    /// Gets core identity dependencies.
    /// </summary>
    public IdentityContext IdentityContext { get; } = identityContext ?? throw new ArgumentNullException(nameof(identityContext));
    /// <summary>
    /// Gets token dependencies.
    /// </summary>
    public SecureTokenContext TokenContext { get; } = tokenContext ?? throw new ArgumentNullException(nameof(tokenContext));
    /// <summary>
    /// Gets infrastructure dependencies.
    /// </summary>
    public IdentityInfrastructureContext Infrastructure { get; } = infrastructure ?? throw new ArgumentNullException(nameof(infrastructure));
    /// <summary>
    /// Gets the session repository.
    /// </summary>
    public IAuthenticationSessionRepository SessionRepository { get; } = sessionRepository ?? throw new ArgumentNullException(nameof(sessionRepository));
    /// <summary>
    /// Gets the password hasher selector.
    /// </summary>
    public PasswordHasherSelector PasswordHasherSelector { get; } = passwordHasherSelector ?? throw new ArgumentNullException(nameof(passwordHasherSelector));
    /// <summary>
    /// Gets audit and notification dependencies.
    /// </summary>
    public IdentityAuditContext Audit { get; } = audit ?? throw new ArgumentNullException(nameof(audit));
    /// <summary>
    /// Gets the remembered MFA device service.
    /// </summary>
    public IRememberedMfaDeviceMutationExecutor? RememberedMfaDeviceService { get; } = rememberedMfaDeviceService;
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
