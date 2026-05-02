using System.Globalization;
using Ashlar.Auditing;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Security.Hashing;

namespace Ashlar.Identity;

/// <summary>
/// Implements provider-neutral authentication session lifecycle operations.
/// </summary>
public sealed class AuthenticationSessionService(
    IAuthenticationSessionRepository repository,
    ISessionTokenHasher tokenHasher,
    ISessionTokenGenerator tokenGenerator,
    AuthenticationSessionOptions? options = null,
    TimeProvider? timeProvider = null,
    ISecurityEventSink? securityEventSink = null)
    : IAuthenticationSessionService
{
    private const int MinimumTokenByteLength = 32;
    private const int MaximumTokenByteLength = 192;
    private readonly IAuthenticationSessionRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly ISessionTokenHasher _tokenHasher = tokenHasher ?? throw new ArgumentNullException(nameof(tokenHasher));
    private readonly ISessionTokenGenerator _tokenGenerator = tokenGenerator ?? throw new ArgumentNullException(nameof(tokenGenerator));
    private readonly AuthenticationSessionOptions _options = ValidateOptions(options ?? new AuthenticationSessionOptions());
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;
    private readonly SecurityEventEmitter _securityEvents = new(securityEventSink, timeProvider ?? TimeProvider.System);

    public async Task<CreateAuthenticationSessionResult> CreateSessionAsync(
        Guid userId,
        CreateAuthenticationSessionRequest request,
        CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty) throw new ArgumentException("User ID cannot be empty.", nameof(userId));
        ArgumentNullException.ThrowIfNull(request);

        var lifetime = request.Lifetime ?? _options.DefaultLifetime;
        if (lifetime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException($"{nameof(request)}.{nameof(request.Lifetime)}", request.Lifetime, "Session lifetime must be positive.");
        }

        var token = _tokenGenerator.GenerateToken(_options.TokenByteLength);
        var tokenHash = _tokenHasher.HashToken(token);
        var now = _timeProvider.GetUtcNow();

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
            CreatedAt = now,
            ExpiresAt = now.Add(lifetime),
            LastSeenAt = null,
            RevokedAt = null,
            RevocationReason = null,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            Metadata = metadata
        };

        await _repository.CreateSessionAsync(session, cancellationToken);
        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.SessionCreated,
            Outcome = SecurityEventOutcomes.Success,
            UserId = userId,
            SessionId = session.Id,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            CorrelationId = request.CorrelationId
        }, cancellationToken);
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

        await TryUpdateLastSeenAsync(session, now, cancellationToken);
        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.SessionValidated,
            Outcome = SecurityEventOutcomes.Success,
            UserId = session.UserId,
            SessionId = session.Id,
            IpAddress = session.IpAddress,
            UserAgent = session.UserAgent
        }, cancellationToken);
        return new ValidateAuthenticationSessionResult(true, session, session.UserId, AuthenticationSessionValidationStatus.Success);
    }

    public async Task<bool> RevokeSessionAsync(
        Guid sessionId,
        string? reason = null,
        CancellationToken cancellationToken = default)
    {
        if (sessionId == Guid.Empty) throw new ArgumentException("Session ID cannot be empty.", nameof(sessionId));

        var revoked = await _repository.RevokeSessionAsync(sessionId, _timeProvider.GetUtcNow(), reason, cancellationToken);
        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.SessionRevoked,
            Outcome = revoked ? SecurityEventOutcomes.Success : SecurityEventOutcomes.Failure,
            SessionId = sessionId,
            Properties = reason == null
                ? null
                : new Dictionary<string, string> { ["reason"] = reason }
        }, cancellationToken);
        return revoked;
    }

    public async Task<int> RevokeSessionsForUserAsync(
        Guid userId,
        string? reason = null,
        CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty) throw new ArgumentException("User ID cannot be empty.", nameof(userId));

        var revoked = await _repository.RevokeSessionsForUserAsync(userId, _timeProvider.GetUtcNow(), reason, cancellationToken);
        var properties = new Dictionary<string, string> { ["count"] = revoked.ToString(CultureInfo.InvariantCulture) };
        if (reason != null)
        {
            properties["reason"] = reason;
        }

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.SessionsRevokedForUser,
            Outcome = SecurityEventOutcomes.Success,
            UserId = userId,
            Properties = properties
        }, cancellationToken);
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
            SessionId = session?.Id,
            IpAddress = session?.IpAddress,
            UserAgent = session?.UserAgent,
            FailureReason = failureReason,
            Properties = new Dictionary<string, string> { ["status"] = status.ToString() }
        }, cancellationToken);
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
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // TODO: Log last-seen update failures when Ashlar has a core logging convention.
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
}
