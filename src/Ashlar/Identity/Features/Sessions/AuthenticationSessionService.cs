using System.Globalization;
using Ashlar.Auditing;
using Ashlar.Identity.Notifications;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Ashlar.Identity.Features.Sessions;

internal sealed class AuthenticationSessionService(
    IAuthenticationSessionRepository repository,
    ISecureTokenHasher tokenHasher,
    ISecureTokenGenerator tokenGenerator,
    IAshlarTransactionProvider transactionProvider,
    AuthenticationSessionServiceDependencies dependencies,
    ILogger<AuthenticationSessionService>? logger = null)
    : IAuthenticationSessionService, IAuthenticationSessionMutationExecutor
{
    internal const string SelfServiceProofPurpose = "session-management";
    private static readonly Action<ILogger, Guid, Guid, Exception?> SessionLastSeenUpdateNotPersisted =
        LoggerMessage.Define<Guid, Guid>(
            LogLevel.Warning,
            new EventId(1000, nameof(SessionLastSeenUpdateNotPersisted)),
            "Authentication session last-seen update was not persisted. SessionId={SessionId} UserId={UserId}");

    private static readonly Action<ILogger, Guid, Guid, Exception?> SessionLastSeenUpdateFailed =
        LoggerMessage.Define<Guid, Guid>(
            LogLevel.Warning,
            new EventId(1001, nameof(SessionLastSeenUpdateFailed)),
            "Authentication session last-seen update failed. SessionId={SessionId} UserId={UserId}");

    private const int MinimumTokenByteLength = 32;
    private const int MaximumTokenByteLength = 192;
    private const int MaxRevocationReasonLength = 512;
    private const int MaxStepUpFactorLength = 128;
    private const string StepUpFactorPropertyName = "factor";
    private const string UserIdCannotBeEmptyMessage = "User ID cannot be empty.";
    private readonly IAuthenticationSessionRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly ISecureTokenHasher _tokenHasher = tokenHasher ?? throw new ArgumentNullException(nameof(tokenHasher));
    private readonly ISecureTokenGenerator _tokenGenerator = tokenGenerator ?? throw new ArgumentNullException(nameof(tokenGenerator));
    private readonly IAshlarTransactionProvider _transactionProvider = transactionProvider ?? throw new ArgumentNullException(nameof(transactionProvider));
    private readonly AuthenticationSessionOptions _options = ValidateOptions(dependencies.Options ?? new AuthenticationSessionOptions());
    private readonly TimeProvider _timeProvider = dependencies.TimeProvider ?? TimeProvider.System;
    private readonly SecurityEventEmitter _securityEvents = new(dependencies.SecurityEventSink, dependencies.TimeProvider ?? TimeProvider.System);
    private readonly ILogger<AuthenticationSessionService> _logger = logger ?? dependencies.Logger ?? NullLogger<AuthenticationSessionService>.Instance;
    private readonly IUserRepository _userRepository = dependencies.UserRepository ?? throw new ArgumentNullException($"{nameof(dependencies)}.{nameof(dependencies.UserRepository)}");
    private readonly SecurityNotificationEmitter _notifications = new(dependencies.NotificationService);
    private readonly IAccountSecurityOperationAuthorizer? _operationAuthorizer = dependencies.OperationAuthorizer;

    public async Task<CreateAuthenticationSessionResult> CreateSessionAsync(
        MfaAuthenticationResult authenticationResult,
        CreateAuthenticationSessionRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authenticationResult);
        var user = authenticationResult.AuthenticationSessionIssuanceUser;
        if (user == null)
        {
            throw new AshlarOperationException(AshlarFailureCodes.ValidationError, "Session issuance requires a successful Ashlar authentication result.");
        }

        ArgumentNullException.ThrowIfNull(request);

        var (lifetime, ipAddress, userAgent, metadata) = ValidateCreateSessionRequest(request);
        return await CreateSessionForAuthenticatedUserAsync(user, request, lifetime, ipAddress, userAgent, metadata, cancellationToken);
    }

    internal async Task<CreateAuthenticationSessionResult> CreateSessionForAuthenticatedUserAsync(
        Guid userId,
        CreateAuthenticationSessionRequest request,
        CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty) throw new ArgumentException(UserIdCannotBeEmptyMessage, nameof(userId));
        ArgumentNullException.ThrowIfNull(request);

        var (lifetime, ipAddress, userAgent, metadata) = ValidateCreateSessionRequest(request);

        var user = await GetUserForTenantValidationAsync(userId, request, ipAddress, userAgent, cancellationToken);
        return await CreateSessionForAuthenticatedUserAsync(user, request, lifetime, ipAddress, userAgent, metadata, cancellationToken);
    }

    private (TimeSpan Lifetime, string? IpAddress, string? UserAgent, string? Metadata) ValidateCreateSessionRequest(CreateAuthenticationSessionRequest request)
    {
        var lifetime = request.Lifetime ?? _options.DefaultLifetime;
        if (lifetime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException($"{nameof(request)}.{nameof(request.Lifetime)}", request.Lifetime, "Session lifetime must be positive.");
        }

        ValidateOptionalProvider(request.PrimaryProvider, $"{nameof(request)}.{nameof(request.PrimaryProvider)}");

        var ipAddress = _options.StoreIpAddress
            ? ValidateOptionalLength(request.IpAddress, _options.MaxIpAddressLength, $"{nameof(request)}.{nameof(request.IpAddress)}")
            : null;
        var userAgent = _options.StoreUserAgent
            ? ValidateOptionalLength(request.UserAgent, _options.MaxUserAgentLength, $"{nameof(request)}.{nameof(request.UserAgent)}")
            : null;
        var metadata = _options.StoreMetadata
            ? ValidateOptionalLength(request.Metadata, _options.MaxMetadataLength, $"{nameof(request)}.{nameof(request.Metadata)}")
            : null;

        return (lifetime, ipAddress, userAgent, metadata);
    }

    private async Task<CreateAuthenticationSessionResult> CreateSessionForAuthenticatedUserAsync(
        IUser user,
        CreateAuthenticationSessionRequest request,
        TimeSpan lifetime,
        string? ipAddress,
        string? userAgent,
        string? metadata,
        CancellationToken cancellationToken)
    {
        var userId = user.Id;
        if (!UserTenantOwnership.Matches(user, request.TenantId))
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.SessionCreated,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                TenantId = request.TenantId,
                IpAddress = ipAddress,
                UserAgent = userAgent,
                CorrelationId = request.CorrelationId,
                FailureReason = AshlarFailureCodes.TenantMismatchValue
            }, cancellationToken);

            throw new AshlarOperationException(AshlarFailureCodes.TenantMismatch, "Session tenant must match the referenced user's tenant.");
        }

        if (!user.CanSignIn())
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.SessionCreated,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                TenantId = request.TenantId,
                IpAddress = ipAddress,
                UserAgent = userAgent,
                CorrelationId = request.CorrelationId,
                FailureReason = user.AccountState.ToSecurityFailureReason()
            }, cancellationToken);

            throw new AshlarOperationException(AshlarFailureCodes.UserNotFoundOrUnavailable, "Session user was not found or cannot currently sign in.");
        }

        var token = _tokenGenerator.GenerateToken(_options.TokenByteLength);
        var tokenHash = _tokenHasher.HashToken(token);
        var now = _timeProvider.GetUtcNow();

        var session = new AuthenticationSession
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            TokenHash = tokenHash,
            TenantId = request.TenantId,
            CreatedAt = now,
            AuthenticatedAt = request.AuthenticatedAt ?? now,
            PrimaryProvider = request.PrimaryProvider,
            AdditionalVerificationAt = null,
            AdditionalVerificationProvider = null,
            AdditionalVerificationFactor = null,
            ExpiresAt = now.Add(lifetime),
            LastSeenAt = null,
            RevokedAt = null,
            RevocationReason = null,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            Metadata = metadata
        };

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        await _repository.CreateSessionAsync(session, cancellationToken);
        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.SessionCreated,
            Outcome = SecurityEventOutcomes.Success,
            UserId = userId,
            TenantId = request.TenantId,
            SessionId = session.Id,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            CorrelationId = request.CorrelationId
        }, cancellationToken);

        transaction.OnCommitted(async ct =>
        {
            await _notifications.NotifyAsync(SecurityNotificationType.SignIn, user, now, sessionId: session.Id, context: new AuthenticationContext(TenantId: request.TenantId, IpAddress: ipAddress, UserAgent: userAgent, CorrelationId: request.CorrelationId), cancellationToken: ct);
        });

        await transaction.CommitAsync(cancellationToken);

        return new CreateAuthenticationSessionResult(token, ToCreatedSession(session) with { RollbackToken = token });
    }

    private async Task<IUser> GetUserForTenantValidationAsync(
        Guid userId,
        CreateAuthenticationSessionRequest request,
        string? ipAddress,
        string? userAgent,
        CancellationToken cancellationToken)
    {
        var user = await _userRepository.GetUserByIdAsync(userId, cancellationToken);
        if (user == null)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.SessionCreated,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                TenantId = request.TenantId,
                IpAddress = ipAddress,
                UserAgent = userAgent,
                CorrelationId = request.CorrelationId,
                FailureReason = AshlarFailureCodes.UserNotFoundValue
            }, cancellationToken);

            throw new AshlarOperationException(AshlarFailureCodes.UserNotFound, "Session user was not found.");
        }

        return user;
    }

    private static CreatedAuthenticationSession ToCreatedSession(AuthenticationSession session)
    {
        return new CreatedAuthenticationSession(
            session.Id,
            session.UserId,
            session.TenantId,
            session.CreatedAt,
            session.AuthenticatedAt,
            session.PrimaryProvider,
            session.ExpiresAt,
            session.IpAddress,
            session.UserAgent,
            session.Metadata);
    }

    public async Task<ValidateAuthenticationSessionResult> ValidateSessionAsync(
        string? token,
        CancellationToken cancellationToken = default) =>
        await ValidateSessionAsync(token, null, cancellationToken);

    private async Task<ValidateAuthenticationSessionResult> ValidateSessionAsync(
        string? token,
        Guid? expectedActorUserId,
        CancellationToken cancellationToken)
    {
        if (!SecureTokenHashing.TryHashToken(_tokenHasher, token, out var tokenHash))
        {
            await RecordSessionValidationFailedAsync(
                AuthenticationSessionValidationStatus.Failed,
                null,
                SecurityEventFailureReasons.SessionValidationFailed,
                cancellationToken);
            return ValidateAuthenticationSessionResult.Failed;
        }

        var session = await _repository.GetSessionByTokenHashAsync(tokenHash, cancellationToken);
        if (session == null)
        {
            await RecordSessionValidationFailedAsync(
                AuthenticationSessionValidationStatus.Failed,
                null,
                SecurityEventFailureReasons.SessionValidationFailed,
                cancellationToken);

            return ValidateAuthenticationSessionResult.Failed;
        }

        if (expectedActorUserId is { } actorUserId && actorUserId != session.UserId)
            throw new AshlarOperationException(AshlarFailureCodes.ValidationError, "Audit actor must match the authenticated session owner.");

        var now = _timeProvider.GetUtcNow();
        if (session.ExpiresAt <= now)
        {
            await RecordSessionValidationFailedAsync(
                AuthenticationSessionValidationStatus.Expired,
                session,
                SecurityEventFailureReasons.SessionExpired,
                cancellationToken);

            return new ValidateAuthenticationSessionResult(false, session, session.UserId, AuthenticationSessionValidationStatus.Expired);
        }

        if (session.RevokedAt != null)
        {
            await RecordSessionValidationFailedAsync(
                AuthenticationSessionValidationStatus.Revoked,
                session,
                SecurityEventFailureReasons.SessionRevoked,
                cancellationToken);

            return new ValidateAuthenticationSessionResult(false, session, session.UserId, AuthenticationSessionValidationStatus.Revoked);
        }

        var user = await _userRepository.GetUserByIdAsync(session.UserId, cancellationToken);
        if (user == null || !user.CanSignIn())
        {
            await RecordSessionValidationFailedAsync(
                AuthenticationSessionValidationStatus.Failed,
                session,
                user == null ? AshlarFailureCodes.UserNotFoundValue : user.AccountState.ToSecurityFailureReason(),
                cancellationToken);

            return new ValidateAuthenticationSessionResult(false, session, session.UserId, AuthenticationSessionValidationStatus.Failed);
        }

        if (!UserTenantOwnership.Matches(user, session.TenantId))
        {
            await RecordSessionValidationFailedAsync(
                AuthenticationSessionValidationStatus.Failed,
                session,
                AshlarFailureCodes.TenantMismatchValue,
                cancellationToken);

            return new ValidateAuthenticationSessionResult(false, session, session.UserId, AuthenticationSessionValidationStatus.Failed);
        }

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        await TryUpdateLastSeenAsync(session, now, cancellationToken);
        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.SessionValidated,
            Outcome = SecurityEventOutcomes.Success,
            UserId = session.UserId,
            TenantId = session.TenantId,
            SessionId = session.Id,
            IpAddress = session.IpAddress,
            UserAgent = session.UserAgent
        }, cancellationToken);

        await transaction.CommitAsync(cancellationToken);
        return new ValidateAuthenticationSessionResult(true, session, session.UserId, AuthenticationSessionValidationStatus.Succeeded)
        {
            ValidatedSession = new ValidatedAuthenticationSession(session)
        };
    }

    public Task<Result<AuthenticationSession>> MarkStepUpVerifiedAsync(
        MfaAuthenticationResult authenticationResult,
        MarkSessionStepUpVerifiedRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authenticationResult);
        var user = authenticationResult.StepUpVerifiedUser;
        if (user == null)
        {
            return Task.FromResult(Result.Failure<AuthenticationSession>(AshlarFailureCodes.StepUpRequired, "Step-up marking requires a successful Ashlar MFA verification result."));
        }

        ArgumentNullException.ThrowIfNull(request);
        var verifiedFactor = ValidateStepUpRequest(request);

        return MarkStepUpVerifiedForVerifiedUserAsync(user, request, verifiedFactor, _timeProvider.GetUtcNow(), cancellationToken);
    }

    internal async Task<Result<AuthenticationSession>> MarkStepUpVerifiedForVerifiedUserAsync(
        Guid userId,
        MarkSessionStepUpVerifiedRequest request,
        CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty) throw new ArgumentException(UserIdCannotBeEmptyMessage, nameof(userId));
        ArgumentNullException.ThrowIfNull(request);
        var verifiedFactor = ValidateStepUpRequest(request);

        var now = _timeProvider.GetUtcNow();
        var userResult = await UserTenantValidator.GetUserInTenantAsync(_userRepository, userId, request.Tenant, cancellationToken);
        if (!userResult.TryGetValue(out var user))
        {
            var failure = userResult.GetFailureOr(AshlarFailureCodes.UserNotFound);
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.SessionStepUpVerified,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                TenantId = request.Tenant?.TenantId,
                SessionId = request.SessionId,
                Provider = request.VerifiedProvider,
                Audit = request.Audit,
                FailureReason = failure.Code.Value,
                Properties = new Dictionary<string, string> { [StepUpFactorPropertyName] = verifiedFactor }
            }, cancellationToken);

            return Result.Failure<AuthenticationSession>(failure);
        }

        return await MarkStepUpVerifiedForVerifiedUserAsync(user, request, verifiedFactor, now, cancellationToken);
    }

    private static string ValidateStepUpRequest(MarkSessionStepUpVerifiedRequest request)
    {
        if (request.SessionId == Guid.Empty) throw new ArgumentException("Session ID cannot be empty.", $"{nameof(request)}.{nameof(request.SessionId)}");
        ValidateStepUpProvider(request.VerifiedProvider, $"{nameof(request)}.{nameof(request.VerifiedProvider)}");
        return ValidateRequiredLength(request.VerifiedFactor, MaxStepUpFactorLength, $"{nameof(request)}.{nameof(request.VerifiedFactor)}");
    }

    private async Task<Result<AuthenticationSession>> MarkStepUpVerifiedForVerifiedUserAsync(
        IUser user,
        MarkSessionStepUpVerifiedRequest request,
        string verifiedFactor,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var userId = user.Id;
        if (!UserTenantOwnership.Matches(user, request.Tenant?.TenantId))
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.SessionStepUpVerified,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                TenantId = request.Tenant?.TenantId,
                SessionId = request.SessionId,
                Provider = request.VerifiedProvider,
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.TenantMismatchValue,
                Properties = new Dictionary<string, string> { [StepUpFactorPropertyName] = verifiedFactor }
            }, cancellationToken);

            return Result.Failure<AuthenticationSession>(AshlarFailureCodes.TenantMismatch, "Session user does not belong to the requested tenant.");
        }

        if (!user.CanSignIn())
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.SessionStepUpVerified,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                TenantId = request.Tenant?.TenantId,
                SessionId = request.SessionId,
                Provider = request.VerifiedProvider,
                Audit = request.Audit,
                FailureReason = user.AccountState.ToSecurityFailureReason(),
                Properties = new Dictionary<string, string> { [StepUpFactorPropertyName] = verifiedFactor }
            }, cancellationToken);

            return Result.Failure<AuthenticationSession>(AshlarFailureCodes.UserNotFoundOrUnavailable, "Session user was not found or cannot currently sign in.");
        }

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        var updated = await _repository.MarkStepUpVerifiedAsync(
            request.SessionId,
            userId,
            now,
            request.VerifiedProvider,
            verifiedFactor,
            cancellationToken);

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.SessionStepUpVerified,
            Outcome = updated == null ? SecurityEventOutcomes.Failure : SecurityEventOutcomes.Success,
            UserId = userId,
            TenantId = updated?.TenantId ?? request.Tenant?.TenantId,
            SessionId = request.SessionId,
            Provider = request.VerifiedProvider,
            Audit = request.Audit,
            FailureReason = updated == null ? AshlarFailureCodes.SessionNotFoundOrInactiveValue : null,
            Properties = new Dictionary<string, string> { [StepUpFactorPropertyName] = verifiedFactor }
        }, cancellationToken);

        await transaction.CommitAsync(cancellationToken);

        return updated == null
            ? Result.Failure<AuthenticationSession>(AshlarFailureCodes.SessionNotFoundOrInactive, "Session was not found, is inactive, or does not belong to the user.")
            : Result.Success(updated);
    }

    public async Task<bool> RevokeSessionForCurrentUserAsync(
        RevokeOwnAuthenticationSessionRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.SessionId == Guid.Empty) throw new ArgumentException("Session ID cannot be empty.", $"{nameof(request)}.{nameof(request.SessionId)}");
        ValidateRevocationReason(request.Reason, nameof(request));
        await ValidateSelfServiceRequestAsync(new SelfServiceRevocationValidationRequest(
            request.ActorUserId, request.ActorTenant, request.CurrentSessionId, request.FreshMfaProof,
            request.Audit, AshlarSecurityEventTypes.SessionRevoked, request.SessionId), cancellationToken);

        await AuthorizeSelfServiceAsync(new AccountSecurityAuthorizationContext(
            request.ActorUserId, request.ActorTenant, request.ActorUserId, request.ActorTenant, false,
            AccountSecurityOperation.RevokeOwnSession, TargetSessionId: request.SessionId, CurrentSessionId: request.CurrentSessionId),
            request.Audit, AshlarSecurityEventTypes.SessionRevoked, request.SessionId, cancellationToken);

        return await RevokeSessionForUserAsync(request.ActorUserId, new RevokeAuthenticationSessionRequest
        {
            SessionId = request.SessionId,
            Tenant = request.ActorTenant,
            Audit = request.Audit,
            Reason = request.Reason
        }, cancellationToken);
    }

    public async Task<int> RevokeOtherSessionsForCurrentUserAsync(
        RevokeOwnOtherAuthenticationSessionsRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateRevocationReason(request.Reason, nameof(request));
        await ValidateSelfServiceRequestAsync(new SelfServiceRevocationValidationRequest(
            request.ActorUserId, request.ActorTenant, request.CurrentSessionId, request.FreshMfaProof,
            request.Audit, AshlarSecurityEventTypes.SessionsRevokedForUser, null), cancellationToken);

        await AuthorizeSelfServiceAsync(new AccountSecurityAuthorizationContext(
            request.ActorUserId, request.ActorTenant, request.ActorUserId, request.ActorTenant, false,
            AccountSecurityOperation.RevokeOwnOtherSessions, CurrentSessionId: request.CurrentSessionId),
            request.Audit, AshlarSecurityEventTypes.SessionsRevokedForUser, null, cancellationToken);

        return await RevokeOtherSessionsAsync(request.ActorUserId, new RevokeOtherAuthenticationSessionsRequest
        {
            CurrentSessionId = request.CurrentSessionId,
            Tenant = request.ActorTenant,
            Audit = request.Audit,
            Reason = request.Reason
        }, cancellationToken);
    }

    public async Task<bool> RevokeCurrentSessionAsync(
        RevokeCurrentAuthenticationSessionRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Token);
        ArgumentNullException.ThrowIfNull(request.Audit);
        ValidateRevocationReason(request.Reason, nameof(request));

        var validation = await ValidateSessionAsync(request.Token, request.Audit.ActorUserId, cancellationToken);
        if (!validation.Succeeded || validation.Session == null) return false;
        var session = validation.Session;

        return await RevokeSessionForUserAsync(session.UserId, new RevokeAuthenticationSessionRequest
        {
            SessionId = session.Id,
            Tenant = session.TenantId is { } tenantId ? new TenantContext(tenantId) : TenantContext.Global,
            Audit = request.Audit,
            Reason = request.Reason
        }, cancellationToken);
    }

    public Task<bool> RevokeIssuedSessionAsync(
        RevokeIssuedAuthenticationSessionRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Session);
        ArgumentNullException.ThrowIfNull(request.Audit);
        if (string.IsNullOrWhiteSpace(request.Session.RollbackToken))
            throw new AshlarOperationException(AshlarFailureCodes.ValidationError, "Session rollback requires the session returned by Ashlar session issuance.");

        return RevokeCurrentSessionAsync(new RevokeCurrentAuthenticationSessionRequest(
            request.Session.RollbackToken, request.Audit, request.Reason), cancellationToken);
    }

    private async Task ValidateSelfServiceRequestAsync(
        SelfServiceRevocationValidationRequest request,
        CancellationToken cancellationToken)
    {
        var (actorUserId, actorTenant, currentSessionId, proof, audit, eventType, targetSessionId) = request;
        if (actorUserId == Guid.Empty) throw new ArgumentException("Actor user ID cannot be empty.", nameof(request));
        ArgumentNullException.ThrowIfNull(actorTenant);
        if (currentSessionId == Guid.Empty) throw new ArgumentException("Current session ID cannot be empty.", nameof(request));
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(audit);
        if (audit.ActorUserId != actorUserId)
        {
            await RecordSelfServiceRevocationFailureAsync(actorUserId, actorTenant, new AuditContext(actorUserId),
                eventType, targetSessionId, AshlarFailureCodes.ValidationError, cancellationToken);
            throw new AshlarOperationException(AshlarFailureCodes.ValidationError, "Audit actor must match the authenticated actor.");
        }
        var failure = FreshVerificationProofValidator.ValidateMfaProof(actorUserId, actorTenant, proof, currentSessionId, _timeProvider.GetUtcNow(), SelfServiceProofPurpose);
        if (failure is { } code)
        {
            await RecordSelfServiceRevocationFailureAsync(actorUserId, actorTenant, audit, eventType, targetSessionId, code, cancellationToken);
            throw new AshlarOperationException(code, "Fresh MFA proof is missing, expired, or does not match the actor and current session.");
        }
    }

    private async ValueTask AuthorizeSelfServiceAsync(AccountSecurityAuthorizationContext context, AuditContext audit,
        string eventType, Guid? targetSessionId, CancellationToken cancellationToken)
    {
        if (_operationAuthorizer == null || !await _operationAuthorizer.AuthorizeAsync(context, cancellationToken))
        {
            await RecordSelfServiceRevocationFailureAsync(context.ActorUserId, context.ActorTenant, audit, eventType,
                targetSessionId, AshlarFailureCodes.ValidationError, cancellationToken);
            throw new AshlarOperationException(AshlarFailureCodes.ValidationError, "Authentication-session operation was not authorized.");
        }
    }

    private Task RecordSelfServiceRevocationFailureAsync(Guid actorUserId, TenantContext actorTenant, AuditContext audit,
        string eventType, Guid? targetSessionId, AshlarFailureCode failure, CancellationToken cancellationToken) =>
        _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = eventType,
            Outcome = SecurityEventOutcomes.Failure,
            UserId = actorUserId,
            TenantId = actorTenant.TenantId,
            SessionId = targetSessionId,
            Audit = audit,
            FailureReason = failure.Value
        }, cancellationToken);

    private sealed record SelfServiceRevocationValidationRequest(
        Guid ActorUserId,
        TenantContext ActorTenant,
        Guid CurrentSessionId,
        FreshMfaVerificationProof Proof,
        AuditContext Audit,
        string EventType,
        Guid? TargetSessionId);

    public async Task<int> RevokeSessionsForUserAsync(
        Guid userId,
        RevokeAuthenticationSessionsForUserRequest request,
        CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty) throw new ArgumentException(UserIdCannotBeEmptyMessage, nameof(userId));
        ArgumentNullException.ThrowIfNull(request);
        request.ThrowIfInvalid();
        ValidateRevocationReason(request.Reason, nameof(request));
        var audit = request.Audit;
        ArgumentNullException.ThrowIfNull(audit);

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        var now = _timeProvider.GetUtcNow();
        var revoked = await _repository.RevokeSessionsForUserAsync(userId, now, request.Reason, request.Tenant, request.IncludeAllTenants, cancellationToken);
        var properties = CreateRevocationScopeProperties(request.Tenant, request.IncludeAllTenants);
        properties["count"] = revoked.ToString(CultureInfo.InvariantCulture);
        if (request.Reason != null)
        {
            properties["reason"] = request.Reason;
        }

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.SessionsRevokedForUser,
            Outcome = SecurityEventOutcomes.Success,
            UserId = userId,
            TenantId = request.AuditTenantId ?? request.Tenant?.TenantId,
            Audit = audit,
            Properties = properties
        }, cancellationToken);

        transaction.OnCommitted(async ct =>
        {
            if (revoked > 0)
            {
                var user = await _userRepository.GetUserByIdAsync(userId, ct);
                if (user != null)
                {
                    await _notifications.NotifyAsync(SecurityNotificationType.AllSessionsRevoked, user, now, context: ToNotificationContext(audit, request.Tenant), metadata: properties, cancellationToken: ct);
                }
            }
        });

        await transaction.CommitAsync(cancellationToken);
        return revoked;
    }

    public async Task<IReadOnlyList<AuthenticationSessionSummary>> ListSessionsForUserAsync(
        Guid userId,
        ListAuthenticationSessionsRequest request,
        CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty) throw new ArgumentException(UserIdCannotBeEmptyMessage, nameof(userId));
        ArgumentNullException.ThrowIfNull(request);

        var now = _timeProvider.GetUtcNow();
        var sessions = await _repository.ListSessionsForUserAsync(userId, request.ActiveOnly, now, cancellationToken);

        return sessions.Select(s => new AuthenticationSessionSummary
        {
            Id = s.Id,
            CreatedAt = s.CreatedAt,
            ExpiresAt = s.ExpiresAt,
            LastSeenAt = s.LastSeenAt,
            RevokedAt = s.RevokedAt,
            RevocationReason = s.RevocationReason,
            IpAddress = s.IpAddress,
            UserAgent = s.UserAgent,
            Metadata = s.Metadata,
            IsCurrent = request.CurrentSessionId.HasValue && s.Id == request.CurrentSessionId.Value,
            IsActive = s.IsActive(now)
        }).ToList().AsReadOnly();
    }

    public async Task<bool> RevokeSessionForUserAsync(
        Guid userId,
        RevokeAuthenticationSessionRequest request,
        CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty) throw new ArgumentException(UserIdCannotBeEmptyMessage, nameof(userId));
        ArgumentNullException.ThrowIfNull(request);
        if (request.SessionId == Guid.Empty) throw new ArgumentException("Session ID cannot be empty.", $"{nameof(request)}.{nameof(request.SessionId)}");
        request.ThrowIfInvalid();
        ValidateRevocationReason(request.Reason, nameof(request));
        var audit = request.Audit;
        ArgumentNullException.ThrowIfNull(audit);

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        var now = _timeProvider.GetUtcNow();
        var auditTenant = request.IncludeAllTenants ? null : request.Tenant;
        var revoked = await _repository.RevokeSessionByIdAsync(request.SessionId, userId, now, request.Reason, request.Tenant, request.IncludeAllTenants, cancellationToken);
        var metadata = CreateRevocationScopeProperties(request.Tenant, request.IncludeAllTenants);
        if (request.Reason != null)
        {
            metadata["reason"] = request.Reason;
        }

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.SessionRevoked,
            Outcome = revoked ? SecurityEventOutcomes.Success : SecurityEventOutcomes.Failure,
            UserId = userId,
            TenantId = auditTenant?.TenantId,
            SessionId = request.SessionId,
            Audit = audit,
            Properties = metadata
        }, cancellationToken);

        transaction.OnCommitted(async ct =>
        {
            if (revoked)
            {
                var user = await _userRepository.GetUserByIdAsync(userId, ct);
                if (user != null)
                {
                    await _notifications.NotifyAsync(SecurityNotificationType.SessionRevoked, user, now, sessionId: request.SessionId, context: ToNotificationContext(audit, auditTenant), metadata: metadata, cancellationToken: ct);
                }
            }
        });

        await transaction.CommitAsync(cancellationToken);
        return revoked;
    }

    public async Task<int> RevokeOtherSessionsAsync(
        Guid userId,
        RevokeOtherAuthenticationSessionsRequest request,
        CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty) throw new ArgumentException(UserIdCannotBeEmptyMessage, nameof(userId));
        ArgumentNullException.ThrowIfNull(request);
        if (request.CurrentSessionId == Guid.Empty) throw new ArgumentException("Current session ID cannot be empty.", nameof(request));
        request.ThrowIfInvalid();
        ValidateRevocationReason(request.Reason, nameof(request));
        var audit = request.Audit;
        ArgumentNullException.ThrowIfNull(audit);

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        var now = _timeProvider.GetUtcNow();
        var auditTenant = request.IncludeAllTenants ? null : request.Tenant;
        var revoked = await _repository.RevokeOtherSessionsForUserAsync(userId, request.CurrentSessionId, now, request.Reason, request.Tenant, request.IncludeAllTenants, cancellationToken);
        var properties = CreateRevocationScopeProperties(request.Tenant, request.IncludeAllTenants);
        properties["count"] = revoked.ToString(CultureInfo.InvariantCulture);
        properties["current_session_id"] = request.CurrentSessionId.ToString();
        if (request.Reason != null)
        {
            properties["reason"] = request.Reason;
        }

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.SessionsRevokedForUser,
            Outcome = SecurityEventOutcomes.Success,
            UserId = userId,
            TenantId = auditTenant?.TenantId,
            Audit = audit,
            Properties = properties
        }, cancellationToken);

        transaction.OnCommitted(async ct =>
        {
            if (revoked > 0)
            {
                var user = await _userRepository.GetUserByIdAsync(userId, ct);
                if (user != null)
                {
                    await _notifications.NotifyAsync(SecurityNotificationType.AllOtherSessionsRevoked, user, now, sessionId: request.CurrentSessionId, context: ToNotificationContext(audit, auditTenant), metadata: properties, cancellationToken: ct);
                }
            }
        });

        await transaction.CommitAsync(cancellationToken);
        return revoked;
    }

    private Task RecordSessionValidationFailedAsync(
        AuthenticationSessionValidationStatus status,
        AuthenticationSession? session,
        string failureReason,
        CancellationToken cancellationToken)
    {
        var eventType = status switch
        {
            AuthenticationSessionValidationStatus.Expired => AshlarSecurityEventTypes.SessionExpired,
            AuthenticationSessionValidationStatus.Revoked => AshlarSecurityEventTypes.SessionRevoked,
            _ => AshlarSecurityEventTypes.SessionValidationFailed
        };

        return _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = eventType,
            Outcome = SecurityEventOutcomes.Failure,
            UserId = session?.UserId,
            TenantId = session?.TenantId,
            SessionId = session?.Id,
            IpAddress = session?.IpAddress,
            UserAgent = session?.UserAgent,
            FailureReason = failureReason,
            Properties = new Dictionary<string, string> { ["status"] = status.ToString() }
        }, cancellationToken);
    }

    private static AuthenticationContext ToNotificationContext(AuditContext audit, TenantContext? tenant = null) =>
        new(
            UserId: audit.ActorUserId,
            TenantId: tenant?.TenantId,
            IpAddress: audit.IpAddress,
            UserAgent: audit.UserAgent,
            CorrelationId: audit.CorrelationId);

    private static Dictionary<string, string> CreateRevocationScopeProperties(TenantContext? tenant, bool includeAllTenants)
    {
        if (includeAllTenants)
        {
            return new Dictionary<string, string> { ["scope"] = "all_tenants" };
        }

        if (tenant is { TenantId: Guid tenantId })
        {
            return new Dictionary<string, string>
            {
                ["scope"] = "tenant",
                ["tenant_id"] = tenantId.ToString()
            };
        }

        return new Dictionary<string, string> { ["scope"] = "global" };
    }

    private async Task TryUpdateLastSeenAsync(AuthenticationSession session, DateTimeOffset now, CancellationToken cancellationToken)
    {
        if (session.LastSeenAt.HasValue && (now - session.LastSeenAt.Value) < _options.LastSeenUpdateThreshold)
        {
            return;
        }

        try
        {
            var updated = await _repository.UpdateSessionLastSeenAsync(session.Id, now, cancellationToken);
            if (updated)
            {
                session.LastSeenAt = now;
            }
            else
            {
                SessionLastSeenUpdateNotPersisted(
                    _logger,
                    session.Id,
                    session.UserId,
                    null);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            SessionLastSeenUpdateFailed(
                _logger,
                session.Id,
                session.UserId,
                ex);
        }
    }

    private static AuthenticationSessionOptions ValidateOptions(AuthenticationSessionOptions options)
    {
        if (options.DefaultLifetime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(options), options.DefaultLifetime, "AuthenticationSessionOptions.DefaultLifetime must be positive.");
        }

        if (options.LastSeenUpdateThreshold < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(options), options.LastSeenUpdateThreshold, "AuthenticationSessionOptions.LastSeenUpdateThreshold cannot be negative.");
        }

        if (options.TokenByteLength < MinimumTokenByteLength)
        {
            throw new ArgumentOutOfRangeException(nameof(options), options.TokenByteLength, $"AuthenticationSessionOptions.TokenByteLength must be at least {MinimumTokenByteLength} bytes.");
        }

        if (options.TokenByteLength > MaximumTokenByteLength)
        {
            throw new ArgumentOutOfRangeException(nameof(options), options.TokenByteLength, $"AuthenticationSessionOptions.TokenByteLength must be no more than {MaximumTokenByteLength} bytes.");
        }

        if (options.MaxIpAddressLength <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options), options.MaxIpAddressLength, "AuthenticationSessionOptions.MaxIpAddressLength must be positive.");
        }

        if (options.MaxUserAgentLength <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options), options.MaxUserAgentLength, "AuthenticationSessionOptions.MaxUserAgentLength must be positive.");
        }

        if (options.MaxMetadataLength <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options), options.MaxMetadataLength, "AuthenticationSessionOptions.MaxMetadataLength must be positive.");
        }

        return options;
    }

    private static string? ValidateOptionalLength(string? value, int maxLength, string parameterName)
    {
        if (value == null)
        {
            return null;
        }

        if (value.Length > maxLength)
        {
            throw new ArgumentException($"{parameterName} cannot exceed {maxLength} characters.", parameterName);
        }

        return value;
    }

    private static string ValidateRequiredLength(string? value, int maxLength, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException($"{parameterName} cannot be empty.", parameterName);
        }

        var trimmed = value.Trim();
        if (trimmed.Length > maxLength)
        {
            throw new ArgumentException($"{parameterName} cannot exceed {maxLength} characters.", parameterName);
        }

        return trimmed;
    }

    private static void ValidateOptionalProvider(AuthenticationProviderKey? provider, string parameterName)
    {
        if (provider is { } value)
        {
            AuthenticationProviderKey.ThrowIfNotConfigured(value, parameterName);
        }
    }

    private static void ValidateStepUpProvider(AuthenticationProviderKey provider, string parameterName)
    {
        AuthenticationProviderKey.ThrowIfNotConfigured(provider, parameterName);
    }

    private static void ValidateRevocationReason(string? reason, string parameterName)
    {
        if (reason?.Length > MaxRevocationReasonLength)
        {
            throw new ArgumentException($"{parameterName} cannot exceed {MaxRevocationReasonLength} characters.", parameterName);
        }
    }
}

internal sealed record AuthenticationSessionServiceDependencies(
    IUserRepository UserRepository,
    AuthenticationSessionOptions? Options = null,
    TimeProvider? TimeProvider = null,
    ISecurityEventSink? SecurityEventSink = null,
    ISecurityNotificationService? NotificationService = null,
    ILogger<AuthenticationSessionService>? Logger = null,
    IAccountSecurityOperationAuthorizer? OperationAuthorizer = null);
