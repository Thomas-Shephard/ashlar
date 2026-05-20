using Ashlar.Auditing;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity.Features.Handshakes;

/// <summary>
/// Provides authentication handshake service behavior.
/// </summary>
public sealed class AuthenticationHandshakeService : IAuthenticationHandshakeService
{
    private const string HandshakeIdProperty = "handshake_id";
    private const int MaxMetadataEntries = 20;
    private const int MaxMetadataKeyLength = 128;
    private const int MaxMetadataValueLength = 512;

    private readonly IAuthenticationHandshakeRepository _repository;
    private readonly ISecureTokenGenerator _tokenGenerator;
    private readonly ISecureTokenHasher _tokenHasher;
    private readonly IAshlarTransactionProvider _transactionProvider;
    private readonly AuthenticationHandshakeOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly SecurityEventEmitter _securityEvents;
    private readonly IAuthenticationRateLimiter? _rateLimiter;
    private readonly IIdentityRepository? _identityRepository;
    private readonly SecurityNotificationEmitter _notifications;

    /// <summary>
    /// Initializes a configured service instance.
    /// </summary>
    /// <param name="repository">The repository value.</param>
    /// <param name="tokenGenerator">The token generator value.</param>
    /// <param name="tokenHasher">The token hasher value.</param>
    /// <param name="transactionProvider">The transaction provider value.</param>
    /// <param name="dependencies">The dependencies value.</param>
    public AuthenticationHandshakeService(
        IAuthenticationHandshakeRepository repository,
        ISecureTokenGenerator tokenGenerator,
        ISecureTokenHasher tokenHasher,
        IAshlarTransactionProvider transactionProvider,
        AuthenticationHandshakeServiceDependencies? dependencies = null)
    {
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
        _tokenGenerator = tokenGenerator ?? throw new ArgumentNullException(nameof(tokenGenerator));
        _tokenHasher = tokenHasher ?? throw new ArgumentNullException(nameof(tokenHasher));
        _transactionProvider = transactionProvider ?? throw new ArgumentNullException(nameof(transactionProvider));
        _options = dependencies?.Options?.Value ?? new AuthenticationHandshakeOptions();
        _timeProvider = dependencies?.TimeProvider ?? TimeProvider.System;
        _securityEvents = new SecurityEventEmitter(dependencies?.SecurityEventSink, _timeProvider);
        _rateLimiter = dependencies?.RateLimiter;
        _identityRepository = dependencies?.IdentityRepository;
        _notifications = new SecurityNotificationEmitter(dependencies?.NotificationService);
    }

    public async Task<Result<AuthenticationHandshakeCreated>> CreateHandshakeAsync(
        CreateAuthenticationHandshakeRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.UserId == Guid.Empty)
        {
            throw new ArgumentException("User ID cannot be empty.", nameof(request));
        }
        ArgumentNullException.ThrowIfNull(request.RequiredFactors);

        var requiredFactors = request.RequiredFactors.ToHashSet();
        if (requiredFactors.Count == 0)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.AuthenticationHandshakeCreated,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = request.UserId,
                Context = request.Context,
                FailureReason = AshlarFailureCodes.NoFactorsSpecified.Value
            }, cancellationToken);
            return Result.Failure<AuthenticationHandshakeCreated>(AshlarFailureCodes.NoFactorsSpecified);
        }

        try
        {
            ValidateMetadata(request.Metadata, nameof(request));
        }
        catch (ArgumentException)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.AuthenticationHandshakeCreated,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = request.UserId,
                Context = request.Context,
                FailureReason = AshlarFailureCodes.InvalidMetadata.Value
            }, cancellationToken);
            return Result.Failure<AuthenticationHandshakeCreated>(AshlarFailureCodes.InvalidMetadata);
        }

        var metadata = NormalizeMetadata(request.Metadata);

        var token = _tokenGenerator.GenerateToken();
        var tokenHash = _tokenHasher.HashToken(token);
        var now = _timeProvider.GetUtcNow();

        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            request.UserId,
            tokenHash,
            now,
            now.Add(_options.Expiry),
            false,
            false,
            requiredFactors,
            new HashSet<string>(),
            metadata);

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        await _repository.CreateAsync(handshake, cancellationToken);

        transaction.OnCommitted(ct => _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.AuthenticationHandshakeCreated,
            Outcome = SecurityEventOutcomes.Success,
            UserId = handshake.UserId,
            Context = request.Context,
            Properties = new Dictionary<string, string>
            {
                [HandshakeIdProperty] = handshake.Id.ToString(),
                ["required_factors"] = string.Join(",", handshake.RequiredFactors)
            }
        }, ct));

        await transaction.CommitAsync(cancellationToken);

        return Result<AuthenticationHandshakeCreated>.Success(new AuthenticationHandshakeCreated(handshake, token));
    }

    public async Task<Result<AuthenticationHandshake>> VerifyFactorAsync(
        VerifyAuthenticationHandshakeRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.IsNullOrWhiteSpace(request.HandshakeToken))
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.AuthenticationHandshakeFailed,
                Outcome = SecurityEventOutcomes.Failure,
                Context = request.Context,
                FailureReason = AshlarFailureCodes.EmptyToken.Value
            }, cancellationToken);
            return Result.Failure<AuthenticationHandshake>(AshlarFailureCodes.EmptyToken);
        }

        var tokenHash = _tokenHasher.HashToken(request.HandshakeToken);

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        var handshake = await _repository.FindByTokenHashAsync(tokenHash, forUpdate: true, cancellationToken);
        if (handshake == null)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.AuthenticationHandshakeFailed,
                Outcome = SecurityEventOutcomes.Failure,
                Context = request.Context,
                FailureReason = AshlarFailureCodes.HandshakeNotFound.Value
            }, cancellationToken);
            return Result.Failure<AuthenticationHandshake>(AshlarFailureCodes.HandshakeNotFound);
        }

        var rateLimitResult = await CheckRateLimitAsync(handshake, request.Context, cancellationToken);
        if (rateLimitResult != null)
        {
            return rateLimitResult;
        }

        var now = _timeProvider.GetUtcNow();
        if (handshake.IsRevoked)
        {
            await RecordHandshakeFailedAsync(handshake, AshlarFailureCodes.HandshakeRevoked, request.Context, cancellationToken);
            return Result.Failure<AuthenticationHandshake>(AshlarFailureCodes.HandshakeRevoked);
        }

        if (handshake.IsCompleted)
        {
            await RecordHandshakeFailedAsync(handshake, AshlarFailureCodes.HandshakeAlreadyCompleted, request.Context, cancellationToken);
            return Result.Failure<AuthenticationHandshake>(AshlarFailureCodes.HandshakeAlreadyCompleted);
        }

        if (handshake.ExpiresAt <= now)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.AuthenticationHandshakeExpired,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = handshake.UserId,
                Context = request.Context,
                Properties = new Dictionary<string, string> { [HandshakeIdProperty] = handshake.Id.ToString() }
            }, cancellationToken);
            return Result.Failure<AuthenticationHandshake>(AshlarFailureCodes.HandshakeExpired);
        }

        if (!handshake.RequiredFactors.Contains(request.FactorType))
        {
            await RecordHandshakeFailedAsync(handshake, AshlarFailureCodes.InvalidFactorType, request.Context, cancellationToken);
            return Result.Failure<AuthenticationHandshake>(AshlarFailureCodes.InvalidFactorType);
        }

        if (handshake.VerifiedFactors.Contains(request.FactorType))
        {
            await RecordHandshakeFailedAsync(handshake, AshlarFailureCodes.FactorAlreadyVerified, request.Context, cancellationToken);
            return Result.Failure<AuthenticationHandshake>(AshlarFailureCodes.FactorAlreadyVerified);
        }

        var verifiedFactors = handshake.VerifiedFactors.ToHashSet();
        verifiedFactors.Add(request.FactorType);

        var isCompleted = handshake.RequiredFactors.All(verifiedFactors.Contains);
        try
        {
            ValidateMetadata(request.Metadata, nameof(request));
        }
        catch (ArgumentException)
        {
            await RecordHandshakeFailedAsync(handshake, AshlarFailureCodes.InvalidMetadata, request.Context, cancellationToken);
            return Result.Failure<AuthenticationHandshake>(AshlarFailureCodes.InvalidMetadata);
        }

        var updatedHandshake = handshake with
        {
            VerifiedFactors = verifiedFactors,
            IsCompleted = isCompleted,
            CompletedAt = isCompleted ? now : handshake.CompletedAt,
            Metadata = MergeMetadata(handshake.Metadata, request.Metadata)
        };

        await _repository.UpdateAsync(updatedHandshake, cancellationToken);

        transaction.OnCommitted(ct => _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = isCompleted ? AshlarSecurityEventTypes.AuthenticationHandshakeCompleted : AshlarSecurityEventTypes.AuthenticationHandshakeFactorVerified,
            Outcome = SecurityEventOutcomes.Success,
            UserId = handshake.UserId,
            Context = request.Context,
            Properties = new Dictionary<string, string>
            {
                [HandshakeIdProperty] = handshake.Id.ToString(),
                ["verified_factor"] = request.FactorType,
                ["is_completed"] = isCompleted.ToString()
            }
        }, ct));

        await transaction.CommitAsync(cancellationToken);

        return Result.Success(updatedHandshake);
    }

    /// <summary>
    /// Performs the get handshake <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="handshakeToken">The handshake token value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<AuthenticationHandshake?> GetHandshakeAsync(string handshakeToken, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(handshakeToken)) return null;
        var tokenHash = _tokenHasher.HashToken(handshakeToken);
        return await _repository.FindByTokenHashAsync(tokenHash, cancellationToken: cancellationToken);
    }

    /// <summary>
    /// Performs the revoke handshake <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="handshakeToken">The handshake token value.</param>
    /// <param name="context">The context value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<Result> RevokeHandshakeAsync(string handshakeToken, AuthenticationContext? context = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(handshakeToken)) return Result.Failure(AshlarFailureCodes.EmptyToken);
        var tokenHash = _tokenHasher.HashToken(handshakeToken);

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        var handshake = await _repository.FindByTokenHashAsync(tokenHash, forUpdate: true, cancellationToken: cancellationToken);
        if (handshake == null) return Result.Failure(AshlarFailureCodes.HandshakeNotFound);
        if (handshake.IsRevoked) return Result.Success();

        var updatedHandshake = handshake with { IsRevoked = true, RevokedAt = _timeProvider.GetUtcNow() };

        await _repository.UpdateAsync(updatedHandshake, cancellationToken);

        transaction.OnCommitted(ct => _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.AuthenticationHandshakeRevoked,
            Outcome = SecurityEventOutcomes.Success,
            UserId = handshake.UserId,
            Context = context,
            Properties = new Dictionary<string, string> { [HandshakeIdProperty] = handshake.Id.ToString() }
        }, ct));

        await transaction.CommitAsync(cancellationToken);
        return Result.Success();
    }

    private Task RecordHandshakeFailedAsync(AuthenticationHandshake handshake, AshlarFailureCode reason, AuthenticationContext? context, CancellationToken cancellationToken)
    {
        return _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.AuthenticationHandshakeFailed,
            Outcome = SecurityEventOutcomes.Failure,
            UserId = handshake.UserId,
            Context = context,
            FailureReason = reason.Value,
            Properties = new Dictionary<string, string> { [HandshakeIdProperty] = handshake.Id.ToString() }
        }, cancellationToken);
    }

    private async Task<Result<AuthenticationHandshake>?> CheckRateLimitAsync(AuthenticationHandshake handshake, AuthenticationContext? context, CancellationToken cancellationToken)
    {
        if (_rateLimiter == null)
        {
            return null;
        }

        var rateLimitAttempt = new RateLimitAttempt
        {
            Key = $"handshake-verify:{handshake.UserId}",
            Purpose = "handshake-verify"
        };

        if (context != null)
        {
            rateLimitAttempt = new RateLimitAttempt
            {
                Key = rateLimitAttempt.Key,
                Purpose = rateLimitAttempt.Purpose,
                IpAddress = context.IpAddress,
                CorrelationId = context.CorrelationId
            };
        }

        var rateLimitDecision = await _rateLimiter.CheckAsync(rateLimitAttempt, _options.VerificationRateLimit, cancellationToken);

        if (rateLimitDecision.IsAllowed)
        {
            return null;
        }

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.AuthenticationHandshakeVerificationRateLimited,
            Outcome = SecurityEventOutcomes.Failure,
            UserId = handshake.UserId,
            Context = context,
            Properties = new Dictionary<string, string> { [HandshakeIdProperty] = handshake.Id.ToString() }
        }, cancellationToken);

        if (_identityRepository != null)
        {
            var user = await _identityRepository.GetUserByIdAsync(handshake.UserId, cancellationToken);
            if (user != null)
            {
                await _notifications.NotifyAsync(SecurityNotificationType.SuspiciousAuthenticationAttempt, user, _timeProvider.GetUtcNow(), cancellationToken: cancellationToken);
            }
        }

        return Result.Failure<AuthenticationHandshake>(AshlarFailureCodes.RateLimitExceeded);
    }

    private static Dictionary<string, string>? MergeMetadata(
        IDictionary<string, string>? existingMetadata,
        IDictionary<string, string>? requestMetadata)
    {
        Dictionary<string, string>? updatedMetadata = NormalizeMetadata(existingMetadata);
        if (requestMetadata == null)
        {
            return updatedMetadata;
        }

        updatedMetadata ??= [];
        foreach (var kvp in requestMetadata)
        {
            updatedMetadata[kvp.Key] = NormalizeMetadataValue(kvp.Value);
        }

        return updatedMetadata;
    }

    private static Dictionary<string, string>? NormalizeMetadata(IDictionary<string, string>? metadata)
    {
        if (metadata == null)
        {
            return null;
        }

        var normalized = new Dictionary<string, string>(metadata.Count, StringComparer.Ordinal);
        foreach (var kvp in metadata)
        {
            normalized[kvp.Key] = NormalizeMetadataValue(kvp.Value);
        }

        return normalized;
    }

    private static void ValidateMetadata(IDictionary<string, string>? metadata, string paramName)
    {
        if (metadata == null)
        {
            return;
        }

        if (metadata.Count > MaxMetadataEntries)
        {
            throw new ArgumentException($"Metadata cannot contain more than {MaxMetadataEntries} entries.", paramName);
        }

        foreach (var kvp in metadata)
        {
            if (string.IsNullOrWhiteSpace(kvp.Key))
            {
                throw new ArgumentException("Metadata keys cannot be null or whitespace.", paramName);
            }

            if (kvp.Key.Length > MaxMetadataKeyLength)
            {
                throw new ArgumentException($"Metadata keys cannot exceed {MaxMetadataKeyLength} characters.", paramName);
            }

            if (GetMetadataValueLength(kvp.Value) > MaxMetadataValueLength)
            {
                throw new ArgumentException($"Metadata values cannot exceed {MaxMetadataValueLength} characters.", paramName);
            }
        }
    }

    private static string NormalizeMetadataValue(string? value) => value ?? string.Empty;

    private static int GetMetadataValueLength(string? value) => value?.Length ?? 0;
}

/// <summary>
/// Represents the authentication handshake service dependencies data model.
/// </summary>
/// <param name="Options">The options value.</param>
/// <param name="TimeProvider">The time provider value.</param>
/// <param name="SecurityEventSink">The security event sink value.</param>
/// <param name="RateLimiter">The rate limiter value.</param>
/// <param name="IdentityRepository">The identity repository value.</param>
/// <param name="NotificationService">The notification service value.</param>
public sealed record AuthenticationHandshakeServiceDependencies(
    IOptions<AuthenticationHandshakeOptions>? Options = null,
    TimeProvider? TimeProvider = null,
    ISecurityEventSink? SecurityEventSink = null,
    IAuthenticationRateLimiter? RateLimiter = null,
    IIdentityRepository? IdentityRepository = null,
    ISecurityNotificationService? NotificationService = null);



