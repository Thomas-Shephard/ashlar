using System.Globalization;
using Ashlar.Auditing;
using Ashlar.Identity.Notifications;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Ashlar.Identity.Features.Sessions;

/// <summary>
/// Implements provider-neutral authentication session lifecycle operations.
/// </summary>
/// <param name="repository">The repository value.</param>
/// <param name="tokenHasher">The token hasher value.</param>
/// <param name="tokenGenerator">The token generator value.</param>
/// <param name="transactionProvider">The transaction provider value.</param>
/// <param name="dependencies">The dependencies value.</param>
/// <param name="logger">The logger value.</param>
public sealed class AuthenticationSessionService(
    IAuthenticationSessionRepository repository,
    ISecureTokenHasher tokenHasher,
    ISecureTokenGenerator tokenGenerator,
    IAshlarTransactionProvider transactionProvider,
    AuthenticationSessionServiceDependencies dependencies,
    ILogger<AuthenticationSessionService>? logger = null)
    : IAuthenticationSessionService
{
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

    /// <summary>
    /// Initializes a configured service instance.
    /// </summary>
    /// <param name="repository">The repository value.</param>
    /// <param name="tokenHasher">The token hasher value.</param>
    /// <param name="tokenGenerator">The token generator value.</param>
    /// <param name="transactionProvider">The transaction provider value.</param>
    public AuthenticationSessionService(
        IAuthenticationSessionRepository repository,
        ISecureTokenHasher tokenHasher,
        ISecureTokenGenerator tokenGenerator,
        IAshlarTransactionProvider transactionProvider)
        : this(repository, tokenHasher, tokenGenerator, transactionProvider, new AuthenticationSessionServiceDependencies())
    {
    }

    private const int MinimumTokenByteLength = 32;
    private const int MaximumTokenByteLength = 192;
    private const int MaxRevocationReasonLength = 512;
    private const int MaxStepUpFactorLength = 128;
    private const string UserIdCannotBeEmptyMessage = "User ID cannot be empty.";
    private readonly IAuthenticationSessionRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly ISecureTokenHasher _tokenHasher = tokenHasher ?? throw new ArgumentNullException(nameof(tokenHasher));
    private readonly ISecureTokenGenerator _tokenGenerator = tokenGenerator ?? throw new ArgumentNullException(nameof(tokenGenerator));
    private readonly IAshlarTransactionProvider _transactionProvider = transactionProvider ?? throw new ArgumentNullException(nameof(transactionProvider));
    private readonly AuthenticationSessionOptions _options = ValidateOptions(dependencies.Options ?? new AuthenticationSessionOptions());
    private readonly TimeProvider _timeProvider = dependencies.TimeProvider ?? TimeProvider.System;
    private readonly SecurityEventEmitter _securityEvents = new(dependencies.SecurityEventSink, dependencies.TimeProvider ?? TimeProvider.System, dependencies.LoggerFactory);
    private readonly ILogger<AuthenticationSessionService> _logger = logger ?? dependencies.Logger ?? NullLogger<AuthenticationSessionService>.Instance;
    private readonly IUserRepository? _userRepository = dependencies.UserRepository;
    private readonly SecurityNotificationEmitter _notifications = new(dependencies.NotificationService);

    public async Task<CreateAuthenticationSessionResult> CreateSessionAsync(
        Guid userId,
        CreateAuthenticationSessionRequest request,
        CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty) throw new ArgumentException(UserIdCannotBeEmptyMessage, nameof(userId));
        ArgumentNullException.ThrowIfNull(request);

        var lifetime = request.Lifetime ?? _options.DefaultLifetime;
        if (lifetime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException($"{nameof(request)}.{nameof(request.Lifetime)}", request.Lifetime, "Session lifetime must be positive.");
        }

        var token = _tokenGenerator.GenerateToken(_options.TokenByteLength);
        var tokenHash = _tokenHasher.HashToken(token);
        var now = _timeProvider.GetUtcNow();
        var additionalVerificationFactor = ValidateOptionalLength(request.AdditionalVerificationFactor, MaxStepUpFactorLength, $"{nameof(request)}.{nameof(request.AdditionalVerificationFactor)}");

        var ipAddress = _options.StoreIpAddress
            ? ValidateOptionalLength(request.IpAddress, _options.MaxIpAddressLength, $"{nameof(request)}.{nameof(request.IpAddress)}")
            : null;
        var userAgent = _options.StoreUserAgent
            ? ValidateOptionalLength(request.UserAgent, _options.MaxUserAgentLength, $"{nameof(request)}.{nameof(request.UserAgent)}")
            : null;
        var metadata = _options.StoreMetadata
            ? ValidateOptionalLength(request.Metadata, _options.MaxMetadataLength, $"{nameof(request)}.{nameof(request.Metadata)}")
            : null;

        var session = new AuthenticationSession
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            TokenHash = tokenHash,
            TenantId = request.TenantId,
            CreatedAt = now,
            AuthenticatedAt = request.AuthenticatedAt ?? now,
            PrimaryProvider = request.PrimaryProvider,
            AdditionalVerificationAt = request.AdditionalVerificationAt,
            AdditionalVerificationProvider = request.AdditionalVerificationProvider,
            AdditionalVerificationFactor = additionalVerificationFactor,
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
        transaction.OnCommitted(async ct =>
        {
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
            }, ct);

            if (_userRepository != null)
            {
                var user = await _userRepository.GetUserByIdAsync(userId, ct);
                if (user != null)
                {
                    await _notifications.NotifyAsync(SecurityNotificationType.SignIn, user, now, sessionId: session.Id, context: new AuthenticationContext(TenantId: request.TenantId, IpAddress: ipAddress, UserAgent: userAgent, CorrelationId: request.CorrelationId), cancellationToken: ct);
                }
            }
        });

        await transaction.CommitAsync(cancellationToken);

        return new CreateAuthenticationSessionResult(token, session);
    }

    public async Task<ValidateAuthenticationSessionResult> ValidateSessionAsync(
        string token,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            await RecordSessionValidationFailedAsync(
                AuthenticationSessionValidationStatus.Failed,
                null,
                SecurityEventFailureReasons.SessionValidationFailed,
                cancellationToken);
            return ValidateAuthenticationSessionResult.Failed;
        }

        string tokenHash;
        try
        {
            tokenHash = _tokenHasher.HashToken(token);
        }
        catch (ArgumentException)
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

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        await TryUpdateLastSeenAsync(session, now, cancellationToken);
        transaction.OnCommitted(ct => _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.SessionValidated,
            Outcome = SecurityEventOutcomes.Success,
            UserId = session.UserId,
            TenantId = session.TenantId,
            SessionId = session.Id,
            IpAddress = session.IpAddress,
            UserAgent = session.UserAgent
        }, ct));

        await transaction.CommitAsync(cancellationToken);
        return new ValidateAuthenticationSessionResult(true, session, session.UserId, AuthenticationSessionValidationStatus.Success);
    }

    public async Task<Result<AuthenticationSession>> MarkStepUpVerifiedAsync(
        Guid userId,
        MarkSessionStepUpVerifiedRequest request,
        CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty) throw new ArgumentException(UserIdCannotBeEmptyMessage, nameof(userId));
        ArgumentNullException.ThrowIfNull(request);
        if (request.SessionId == Guid.Empty) throw new ArgumentException("Session ID cannot be empty.", $"{nameof(request)}.{nameof(request.SessionId)}");
        ValidateStepUpProvider(request.VerifiedProvider, $"{nameof(request)}.{nameof(request.VerifiedProvider)}");
        var verifiedFactor = ValidateRequiredLength(request.VerifiedFactor, MaxStepUpFactorLength, $"{nameof(request)}.{nameof(request.VerifiedFactor)}");

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        var now = _timeProvider.GetUtcNow();
        var updated = await _repository.MarkStepUpVerifiedAsync(
            request.SessionId,
            userId,
            now,
            request.VerifiedProvider,
            verifiedFactor,
            cancellationToken);

        transaction.OnCommitted(ct => _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.SessionStepUpVerified,
            Outcome = updated == null ? SecurityEventOutcomes.Failure : SecurityEventOutcomes.Success,
            UserId = userId,
            TenantId = updated?.TenantId ?? request.Tenant?.TenantId,
            SessionId = request.SessionId,
            Provider = request.VerifiedProvider,
            Audit = request.Audit,
            Properties = new Dictionary<string, string> { ["factor"] = verifiedFactor }
        }, ct));

        await transaction.CommitAsync(cancellationToken);

        return updated == null
            ? Result.Failure<AuthenticationSession>(AshlarFailureCodes.SessionNotFoundOrInactive, "Session was not found, is inactive, or does not belong to the user.")
            : Result.Success(updated);
    }

    public async Task<bool> RevokeSessionAsync(
        Guid sessionId,
        string? reason = null,
        AuditContext? audit = null,
        CancellationToken cancellationToken = default)
    {
        if (sessionId == Guid.Empty) throw new ArgumentException("Session ID cannot be empty.", nameof(sessionId));
        ValidateRevocationReason(reason, nameof(reason));

        var session = await _repository.GetSessionAsync(sessionId, cancellationToken);

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        var now = _timeProvider.GetUtcNow();
        var revoked = session != null && await _repository.RevokeSessionAsync(sessionId, now, reason, cancellationToken);
        transaction.OnCommitted(ct => RecordSessionRevocationCommittedAsync(sessionId, session, revoked, reason, audit, now, ct));

        await transaction.CommitAsync(cancellationToken);
        return revoked;
    }

    private async Task RecordSessionRevocationCommittedAsync(
        Guid sessionId,
        AuthenticationSession? session,
        bool revoked,
        string? reason,
        AuditContext? audit,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var metadata = reason == null ? null : new Dictionary<string, string> { ["reason"] = reason };
        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.SessionRevoked,
            Outcome = revoked ? SecurityEventOutcomes.Success : SecurityEventOutcomes.Failure,
            UserId = session?.UserId,
            TenantId = session?.TenantId,
            SessionId = sessionId,
            Audit = audit,
            IpAddress = session?.IpAddress,
            UserAgent = session?.UserAgent,
            Properties = metadata
        }, cancellationToken);

        if (!revoked || session == null || _userRepository == null)
        {
            return;
        }

        var user = await _userRepository.GetUserByIdAsync(session.UserId, cancellationToken);
        if (user != null)
        {
            await _notifications.NotifyAsync(SecurityNotificationType.SessionRevoked, user, now, sessionId: sessionId, metadata: metadata, cancellationToken: cancellationToken);
        }
    }

    public async Task<int> RevokeSessionsForUserAsync(
        Guid userId,
        string? reason = null,
        TenantContext? tenant = null,
        AuditContext? audit = null,
        CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty) throw new ArgumentException(UserIdCannotBeEmptyMessage, nameof(userId));
        ValidateRevocationReason(reason, nameof(reason));

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        var now = _timeProvider.GetUtcNow();
        var revoked = await _repository.RevokeSessionsForUserAsync(userId, now, reason, tenant, cancellationToken);
        var properties = new Dictionary<string, string> { ["count"] = revoked.ToString(CultureInfo.InvariantCulture) };
        if (reason != null)
        {
            properties["reason"] = reason;
        }

        transaction.OnCommitted(async ct =>
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.SessionsRevokedForUser,
                Outcome = SecurityEventOutcomes.Success,
                UserId = userId,
                TenantId = tenant?.TenantId,
                Audit = audit,
                Properties = properties
            }, ct);

            if (revoked > 0 && _userRepository != null)
            {
                var user = await _userRepository.GetUserByIdAsync(userId, ct);
                if (user != null)
                {
                    await _notifications.NotifyAsync(SecurityNotificationType.AllSessionsRevoked, user, now, context: ToNotificationContext(audit, tenant), metadata: properties, cancellationToken: ct);
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
        ValidateRevocationReason(request.Reason, nameof(request));

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        var now = _timeProvider.GetUtcNow();
        var revoked = await _repository.RevokeSessionByIdAsync(request.SessionId, userId, now, request.Reason, request.Tenant, cancellationToken);
        transaction.OnCommitted(async ct =>
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.SessionRevoked,
                Outcome = revoked ? SecurityEventOutcomes.Success : SecurityEventOutcomes.Failure,
                UserId = userId,
                TenantId = request.Tenant?.TenantId,
                SessionId = request.SessionId,
                Audit = request.Audit,
                Properties = request.Reason == null
                    ? null
                    : new Dictionary<string, string> { ["reason"] = request.Reason }
            }, ct);

            if (revoked && _userRepository != null)
            {
                var user = await _userRepository.GetUserByIdAsync(userId, ct);
                if (user != null)
                {
                    await _notifications.NotifyAsync(SecurityNotificationType.SessionRevoked, user, now, sessionId: request.SessionId, context: ToNotificationContext(request.Audit, request.Tenant), metadata: request.Reason == null ? null : new Dictionary<string, string> { ["reason"] = request.Reason }, cancellationToken: ct);
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
        ValidateRevocationReason(request.Reason, nameof(request));

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        var now = _timeProvider.GetUtcNow();
        var revoked = await _repository.RevokeOtherSessionsForUserAsync(userId, request.CurrentSessionId, now, request.Reason, request.Tenant, cancellationToken);
        var properties = new Dictionary<string, string>
        {
            ["count"] = revoked.ToString(CultureInfo.InvariantCulture),
            ["current_session_id"] = request.CurrentSessionId.ToString()
        };
        if (request.Reason != null)
        {
            properties["reason"] = request.Reason;
        }

        transaction.OnCommitted(async ct =>
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.SessionsRevokedForUser,
                Outcome = SecurityEventOutcomes.Success,
                UserId = userId,
                TenantId = request.Tenant?.TenantId,
                Audit = request.Audit,
                Properties = properties
            }, ct);

            if (revoked > 0 && _userRepository != null)
            {
                var user = await _userRepository.GetUserByIdAsync(userId, ct);
                if (user != null)
                {
                    await _notifications.NotifyAsync(SecurityNotificationType.AllOtherSessionsRevoked, user, now, sessionId: request.CurrentSessionId, context: ToNotificationContext(request.Audit, request.Tenant), metadata: properties, cancellationToken: ct);
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

    private static AuthenticationContext? ToNotificationContext(AuditContext? audit, TenantContext? tenant = null)
    {
        if (audit == null && tenant == null) return new AuthenticationContext();
        Guid? tenantId = null;
        if (tenant != null)
        {
            tenantId = tenant.TenantId;
        }

        if (audit == null) return new AuthenticationContext(TenantId: tenantId);

        return new AuthenticationContext(
            UserId: audit.ActorUserId,
            TenantId: tenantId,
            IpAddress: audit.IpAddress,
            UserAgent: audit.UserAgent,
            CorrelationId: audit.CorrelationId);
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

    private static void ValidateStepUpProvider(AuthenticationProviderKey provider, string parameterName)
    {
        if (provider.Type == default || string.IsNullOrWhiteSpace(provider.Name))
        {
            throw new ArgumentException("Verified provider cannot be empty.", parameterName);
        }
    }

    private static void ValidateRevocationReason(string? reason, string parameterName)
    {
        if (reason?.Length > MaxRevocationReasonLength)
        {
            throw new ArgumentException($"{parameterName} cannot exceed {MaxRevocationReasonLength} characters.", parameterName);
        }
    }
}

/// <summary>
/// Represents the authentication session service dependencies data model.
/// </summary>
/// <param name="Options">The options value.</param>
/// <param name="TimeProvider">The time provider value.</param>
/// <param name="SecurityEventSink">The security event sink value.</param>
/// <param name="UserRepository">Looks up users when operations need notification context.</param>
/// <param name="NotificationService">The notification service value.</param>
/// <param name="Logger">Receives operational messages emitted directly by the session service.</param>
/// <param name="LoggerFactory">Creates diagnostics for embedded security event sink failures.</param>
public sealed record AuthenticationSessionServiceDependencies(
    AuthenticationSessionOptions? Options = null,
    TimeProvider? TimeProvider = null,
    ISecurityEventSink? SecurityEventSink = null,
    IUserRepository? UserRepository = null,
    ISecurityNotificationService? NotificationService = null,
    ILogger<AuthenticationSessionService>? Logger = null,
    ILoggerFactory? LoggerFactory = null);
